-- handler.lua
local http = require "resty.http"
local cjson = require "cjson.safe"

local VaultAppRoleHandler = {VERSION = "1.0.0", PRIORITY = 1000}

-- Cache cho Vault token và secrets
local vault_token_cache = {}
local secrets_cache = {}
local CACHE_TTL = 300 -- 5 phút

-- Hàm lấy Vault token từ AppRole
local function get_vault_token(vault_addr, role_id, secret_id)
    local cache_key = role_id
    local cached = vault_token_cache[cache_key]
    if cached and (ngx.now() - cached.time) < CACHE_TTL then
        kong.log.debug("Using cached Vault token")
        return cached.token, nil
    end
    kong.log.info("Authenticating with Vault AppRole")

    local httpc = http.new()
    httpc:set_timeout(5000)
    local url = vault_addr .. "/v1/auth/approle/login"
    local res, err = httpc:request_uri(url, {
        method = "POST",
        body = cjson.encode({role_id = role_id, secret_id = secret_id}),
        headers = {["Content-Type"] = "application/json"},
        ssl_verify = false -- Thay đổi thành true trong production
    })
    if not res then
        kong.log.err("Failed to connect to Vault: ", err or "unknown error")
        return nil, "Failed to connect to Vault: " .. (err or "unknown error")
    end
    if res.status ~= 200 then
        kong.log.err("Vault authentication failed: ", res.body)
        return nil, "Vault authentication failed with status " .. res.status
    end
    local response, decode_err = cjson.decode(res.body)
    if not response then
        kong.log.err("Failed to decode Vault response: ", decode_err)
        return nil, "Failed to decode Vault response"
    end
    local token = response.auth and response.auth.client_token
    if not token then
        kong.log.err("No client_token in Vault response")
        return nil, "No client_token in Vault response"
    end
    -- Cache token
    vault_token_cache[cache_key] = {token = token, time = ngx.now()}
    kong.log.info("Successfully authenticated with Vault")
    return token, nil
end

-- Hàm lấy secret từ Vault
local function get_secret_from_vault(vault_addr, vault_token, data_path, key)
    local cache_key = data_path .. "/" .. key
    local cached = secrets_cache[cache_key]
    if cached and (ngx.now() - cached.time) < CACHE_TTL then
        kong.log.debug("Using cached secret for key: ", key)
        return cached.value, nil
    end
    kong.log.info("Fetching secret from Vault: ", data_path, "/", key)
    local httpc = http.new()
    httpc:set_timeout(5000)
    local vault_path = vault_addr .. "/v1/" .. data_path
    local res, err = httpc:request_uri(vault_path, {
        method = "GET",
        headers = {["X-Vault-Token"] = vault_token},
        ssl_verify = false -- Thay đổi thành true trong production
    })
    if not res then
        kong.log.err("Failed to fetch secret from Vault: ",
                     err or "unknown error")
        return nil, "Failed to fetch secret from Vault: " ..
                   (err or "unknown error")
    end
    if res.status ~= 200 then
        kong.log.err("Vault secret fetch failed: ", res.body)
        return nil, "Vault secret fetch failed with status " .. res.status
    end
    local response, decode_err = cjson.decode(res.body)
    if not response then
        kong.log.err("Failed to decode Vault secret response: ", decode_err)
        return nil, "Failed to decode Vault secret response"
    end
    -- Xử lý KV v2 (data.data) hoặc KV v1 (data)
    local data = response.data
    if data and data.data then
        data = data.data -- KV v2
    end
    local value = data and data[key]
    if not value then
        kong.log
            .err("Key '", key, "' not found in Vault path '", data_path, "'")
        return nil,
               "Key '" .. key .. "' not found in Vault path '" .. data_path ..
                   "'"
    end
    -- Cache secret
    secrets_cache[cache_key] = {value = value, time = ngx.now()}
    kong.log.info("Successfully fetched secret for key: ", key)
    return value, nil
end

-- Hàm parse vault reference: {vault://path#key}
local function parse_vault_reference(ref)
    if type(ref) ~= "string" then return nil, nil end

    local pattern = "{vault://([^#]+)#([^}]+)}"
    local path, key = string.match(ref, pattern)
    return path, key
end

-- Phase: access - kiểm tra và inject secrets
-- Thay vì: function VaultAppRoleHandler:access(config)
  -- function VaultAppRoleHandler:access(config)
function VaultAppRoleHandler.access(_, config)
    -- Lấy Vault token
    local vault_token, err = get_vault_token(config.vault_addr,
                                             config.vault_role_id,
                                             config.vault_secret_id)
    if not vault_token then
        kong.log.err("Failed to get Vault token: ", err)
        return kong.response.exit(500, {
            message = "Internal server error: Failed to authenticate with Vault"
        })
    end
    -- Kiểm tra và thay thế các giá trị secret trong headers
    local headers = kong.request.get_headers()
    for header_name, header_value in pairs(headers) do
        if type(header_value) == "string" then
            local path, key = parse_vault_reference(header_value)
            if path and key then
                kong.log.debug("Found Vault reference in header: ", header_name)
                local secret_value, secret_err =
                    get_secret_from_vault(config.vault_addr, vault_token, path,
                                          key)

                if secret_value then
                    kong.service.request.set_header(header_name, secret_value)
                    kong.log.info("Replaced header '", header_name,
                                  "' with Vault secret")
                else
                    kong.log.err("Failed to get secret for header '",
                                 header_name, "': ", secret_err)
                end
            end
        end
    end
    -- Kiểm tra API key nếu được cấu hình
    if config.api_key_header then
        local api_key = kong.request.get_header(config.api_key_header)

        if not api_key then
            return kong.response.exit(401, {message = "Missing API key"})
        end
        -- Kiểm tra xem API key có phải là vault reference không
        local path, key = parse_vault_reference(config.expected_api_key)

        local expected_key
        if path and key then
            expected_key, err = get_secret_from_vault(config.vault_addr,
                                                      vault_token, path, key)
            if not expected_key then
                kong.log.err("Failed to get expected API key from Vault: ", err)
                return kong.response.exit(500,
                                          {message = "Internal server error"})
            end
        else
            expected_key = config.expected_api_key
        end
        if api_key ~= expected_key then
            return kong.response.exit(401, {message = "Invalid API key"})
        end

        kong.log.info("API key validated successfully")
    end
end

return VaultAppRoleHandler
