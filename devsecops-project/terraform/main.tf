# ============================================================
# Terraform - Azure Infrastructure for DevSecOps Project
# Resources: ACR, Container Apps, Key Vault, Log Analytics
# ============================================================

terraform {
  required_version = ">= 1.7.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Store state in Azure Blob Storage (not locally)
  backend "azurerm" {
    resource_group_name  = "rg-terraform-state"
    storage_account_name = "tfstatedevsecops"
    container_name       = "tfstate"
    key                  = "devsecops.tfstate"
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = false
    }
  }
}

# ── Variables ────────────────────────────────────────────────
variable "location" {
  description = "Azure region"
  type        = string
  default     = "eastus"
}

variable "environment" {
  description = "Environment name (prod/staging)"
  type        = string
  default     = "prod"
}

variable "project_name" {
  description = "Project identifier"
  type        = string
  default     = "devsecops"
}

# ── Resource Group ───────────────────────────────────────────
resource "azurerm_resource_group" "main" {
  name     = "rg-${var.project_name}-${var.environment}"
  location = var.location

  tags = {
    project     = var.project_name
    environment = var.environment
    managed_by  = "terraform"
  }
}

# ── Azure Container Registry ─────────────────────────────────
resource "azurerm_container_registry" "acr" {
  name                = "acr${var.project_name}${var.environment}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "Standard"
  admin_enabled       = true  # Required for Container Apps pull

  # Enable vulnerability scanning
  retention_policy {
    days    = 30
    enabled = true
  }

  tags = azurerm_resource_group.main.tags
}

# ── Log Analytics Workspace ───────────────────────────────────
resource "azurerm_log_analytics_workspace" "logs" {
  name                = "law-${var.project_name}-${var.environment}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "PerGB2018"
  retention_in_days   = 90

  tags = azurerm_resource_group.main.tags
}

# ── Container Apps Environment ────────────────────────────────
resource "azurerm_container_app_environment" "env" {
  name                       = "cae-${var.project_name}-${var.environment}"
  resource_group_name        = azurerm_resource_group.main.name
  location                   = azurerm_resource_group.main.location
  log_analytics_workspace_id = azurerm_log_analytics_workspace.logs.id

  tags = azurerm_resource_group.main.tags
}

# ── Azure Key Vault ───────────────────────────────────────────
data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "kv" {
  name                        = "kv-${var.project_name}-${var.environment}"
  resource_group_name         = azurerm_resource_group.main.name
  location                    = azurerm_resource_group.main.location
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  sku_name                    = "standard"
  soft_delete_retention_days  = 90
  purge_protection_enabled    = true

  # Deny public access by default
  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    secret_permissions = ["Get", "Set", "List", "Delete"]
  }

  tags = azurerm_resource_group.main.tags
}

# ── Container App ─────────────────────────────────────────────
resource "azurerm_container_app" "app" {
  name                         = "ca-privacy-app-${var.environment}"
  container_app_environment_id = azurerm_container_app_environment.env.id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Single"

  registry {
    server               = azurerm_container_registry.acr.login_server
    username             = azurerm_container_registry.acr.admin_username
    password_secret_name = "acr-password"
  }

  secret {
    name  = "acr-password"
    value = azurerm_container_registry.acr.admin_password
  }

  secret {
    name  = "encryption-key"
    value = "REPLACE_WITH_KEYVAULT_REFERENCE"  # Use Key Vault reference in prod
  }

  secret {
    name  = "secret-token"
    value = "REPLACE_WITH_KEYVAULT_REFERENCE"
  }

  template {
    min_replicas = 1
    max_replicas = 5

    container {
      name   = "privacy-app"
      image  = "${azurerm_container_registry.acr.login_server}/privacy-preserving-app:latest"
      cpu    = 0.5
      memory = "1Gi"

      env {
        name        = "ENCRYPTION_KEY"
        secret_name = "encryption-key"
      }

      env {
        name        = "SECRET_TOKEN"
        secret_name = "secret-token"
      }

      liveness_probe {
        transport        = "HTTP"
        path             = "/health"
        port             = 8080
        initial_delay    = 10
        period_seconds   = 30
        failure_count_threshold = 3
      }

      readiness_probe {
        transport      = "HTTP"
        path           = "/health"
        port           = 8080
        period_seconds = 10
      }

      resources {
        cpu    = 0.5
        memory = "1Gi"
      }
    }

    # Auto-scale on HTTP requests
    custom_scale_rule {
      name             = "http-scaler"
      custom_rule_type = "http"
      metadata = {
        concurrentRequests = "50"
      }
    }
  }

  ingress {
    external_enabled = true
    target_port      = 8080

    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  tags = azurerm_resource_group.main.tags
}

# ── Outputs ───────────────────────────────────────────────────
output "acr_login_server" {
  description = "ACR login server URL"
  value       = azurerm_container_registry.acr.login_server
}

output "app_url" {
  description = "Container App public URL"
  value       = "https://${azurerm_container_app.app.ingress[0].fqdn}"
}

output "resource_group" {
  description = "Resource group name"
  value       = azurerm_resource_group.main.name
}

output "key_vault_uri" {
  description = "Key Vault URI for secrets"
  value       = azurerm_key_vault.kv.vault_uri
  sensitive   = true
}
