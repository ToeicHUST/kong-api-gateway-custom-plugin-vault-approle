-- schema.lua
local typedefs = require "kong.db.schema.typedefs"

return {
    name = "kong-api-gateway-custom-plugin-vault-approle",
    fields = {
        {consumer = typedefs.no_consumer},
        {protocols = typedefs.protocols_http}, {
            config = {
                type = "record",
                fields = {
                    -- Vault connection settings
                    {
                        vault_addr = {
                            type = "string",
                            required = true,
                            default = "https://vault.toeichust.me",
                            description = "Vault server address (e.g., https://vault.toeichust.me)"
                        }
                    }, -- Vault AppRole authentication
                    {
                        vault_role_id = {
                            type = "string",
                            required = true,
                            description = "Vault AppRole Role ID"
                        }
                    }, {
                        vault_secret_id = {
                            type = "string",
                            required = true,
                            encrypted = true,
                            referenceable = true,
                            description = "Vault AppRole Secret ID (will be encrypted)"
                        }
                    }, -- Vault data path
                    {
                        vault_data_path = {
                            type = "string",
                            default = "secret/data/dev/config",
                            description = "Vault KV path to fetch secrets (e.g., secret/data/dev/config for KV v2)"
                        }
                    }, -- Optional API key validation
                    {
                        api_key_header = {
                            type = "string",
                            description = "Header name to check for API key (e.g., 'X-API-Key' or 'apikey')"
                        }
                    }, {
                        expected_api_key = {
                            type = "string",
                            encrypted = true,
                            referenceable = true,
                            description = "Expected API key value or Vault reference {vault://path#key}"
                        }
                    }, -- Cache settings
                    {
                        cache_ttl = {
                            type = "number",
                            default = 300,
                            description = "Cache TTL in seconds for Vault tokens and secrets"
                        }
                    }
                }
            }
        }
    }
}
