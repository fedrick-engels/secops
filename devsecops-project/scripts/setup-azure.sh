#!/usr/bin/env bash
# =============================================================
# setup-azure.sh
# One-time Azure infrastructure bootstrap script
# Run this ONCE to set up the environment before CI/CD kicks in
# =============================================================

set -euo pipefail

# ── Config (edit these) ───────────────────────────────────────
PROJECT="devsecops"
ENV="prod"
LOCATION="eastus"
RESOURCE_GROUP="rg-${PROJECT}-${ENV}"
ACR_NAME="acr${PROJECT}${ENV}"
KEYVAULT_NAME="kv-${PROJECT}-${ENV}"

echo "🚀 Setting up Azure DevSecOps infrastructure..."

# ── 1. Create Resource Group ──────────────────────────────────
echo "📦 Creating resource group: $RESOURCE_GROUP"
az group create \
  --name "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --tags project="$PROJECT" environment="$ENV" managed_by="terraform"

# ── 2. Create Terraform state storage ────────────────────────
echo "🗄️  Creating Terraform state storage..."
STATE_RG="rg-terraform-state"
STATE_SA="tfstatedevsecops"

az group create --name "$STATE_RG" --location "$LOCATION" || true
az storage account create \
  --name "$STATE_SA" \
  --resource-group "$STATE_RG" \
  --location "$LOCATION" \
  --sku Standard_LRS \
  --encryption-services blob
az storage container create \
  --name "tfstate" \
  --account-name "$STATE_SA"

# ── 3. Create Service Principal for GitHub Actions ────────────
echo "🔑 Creating service principal for GitHub Actions..."
SP_OUTPUT=$(az ad sp create-for-rbac \
  --name "sp-github-actions-${PROJECT}" \
  --role "Contributor" \
  --scopes "/subscriptions/$(az account show --query id -o tsv)/resourceGroups/$RESOURCE_GROUP" \
  --sdk-auth)

echo ""
echo "══════════════════════════════════════════════════════════"
echo "  ✅ SERVICE PRINCIPAL CREATED"
echo "  Add this JSON as GitHub Secret: AZURE_CREDENTIALS"
echo "══════════════════════════════════════════════════════════"
echo "$SP_OUTPUT"
echo ""

# ── 4. Run Terraform ─────────────────────────────────────────
echo "🏗️  Initializing Terraform..."
cd terraform/
terraform init
terraform plan -var="location=$LOCATION" -var="environment=$ENV"
terraform apply -auto-approve -var="location=$LOCATION" -var="environment=$ENV"

# ── 5. Generate encryption key & store in Key Vault ──────────
echo "🔐 Generating encryption key and storing in Key Vault..."
ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
SECRET_TOKEN=$(python3 -c "import secrets; print(secrets.token_hex(32))")

az keyvault secret set --vault-name "$KEYVAULT_NAME" --name "encryption-key" --value "$ENCRYPTION_KEY"
az keyvault secret set --vault-name "$KEYVAULT_NAME" --name "secret-token" --value "$SECRET_TOKEN"

# ── 6. Print GitHub Secrets needed ───────────────────────────
ACR_SERVER=$(az acr show --name "$ACR_NAME" --query loginServer -o tsv)
ACR_USER=$(az acr credential show --name "$ACR_NAME" --query username -o tsv)
ACR_PASS=$(az acr credential show --name "$ACR_NAME" --query "passwords[0].value" -o tsv)

echo ""
echo "══════════════════════════════════════════════════════════"
echo "  📋 ADD THESE AS GITHUB SECRETS"
echo "  (Settings → Secrets → Actions → New repository secret)"
echo "══════════════════════════════════════════════════════════"
echo "  ACR_LOGIN_SERVER  = $ACR_SERVER"
echo "  ACR_USERNAME      = $ACR_USER"
echo "  ACR_PASSWORD      = $ACR_PASS"
echo "  TEST_ENCRYPTION_KEY = $ENCRYPTION_KEY"
echo "  TEST_SECRET_TOKEN   = $SECRET_TOKEN"
echo "  SNYK_TOKEN          = <get from snyk.io/account>"
echo "══════════════════════════════════════════════════════════"
echo ""
echo "✅ Infrastructure setup complete!"
