package = "kong-api-gateway-custom-plugin-vault-approle"
version = "1.0.0-1"

source = {
  url = "git://github.com/ToeicHUST/kong-api-gateway-custom-plugin-vault-approle",
  tag = "1.0.0"
}

description = {
  summary = "Kong plugin for managing secrets with HashiCorp Vault AppRole authentication",
  detailed = [[
    This plugin integrates Kong API Gateway with HashiCorp Vault using AppRole authentication.
    It automatically fetches secrets from Vault and injects them into requests, replacing
    Vault references with actual secret values. Supports encryption when dumping configurations.
  ]],
  homepage = "https://github.com/ToeicHUST/kong-api-gateway-custom-plugin-vault-approle",
  license = "Apache 2.0"
}

dependencies = {
  "lua >= 5.1"
}

build = {
  type = "builtin",
  modules = {
    ["kong.plugins.kong-api-gateway-custom-plugin-vault-approle.handler"] = "code/handler.lua",
    ["kong.plugins.kong-api-gateway-custom-plugin-vault-approle.schema"] = "code/schema.lua"
  }
}