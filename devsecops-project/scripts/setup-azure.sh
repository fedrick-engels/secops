#!/usr/bin/env bash
set -euo pipefail

PROJECT="devsecops"
ENV="prod"
LOCATION="eastus"
RESOURCE_GROUP="rg-${PROJECT}-${ENV}"
ACR_NAME="acr${PROJECT}${ENV}"
KEYVAULT_NAME="kv-${PROJECT}-${ENV}"

echo "🚀 Setting up Azure DevSecOps infrastructure..."

SUBSCRIPTION_ID=$(az account show --query id -o tsv)
echo "✅ Using subscription: $SUBSCRIPTION_ID"

echo "📦 Creating resource group..."
az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --output table

echo "🐳 Creating Container Registry..."
az acr create --name "$ACR_NAME" --resource-group "$RESOURCE_GROUP" --sku Standard --admin-enabled true --location "$LOCATION" --output table

echo "🔑 Creating Key Vault..."
az keyvault create --name "$KEYVAULT_NAME" --resource-group "$RESOURCE_GROUP" --location "$LOCATION" --sku standard --output table

echo "🔐 Generating encryption keys..."
ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
SECRET_TOKEN=$(python3 -c "import secrets; print(secrets.token_hex(32))")

az keyvault secret set --vault-name "$KEYVAULT_NAME" --name "encryption-key" --value "$ENCRYPTION_KEY" --output table
az keyvault secret set --vault-name "$KEYVAULT_NAME" --name "secret-token" --value "$SECRET_TOKEN" --output table

echo "👤 Creating service principal..."
SP_OUTPUT=$(az ad sp create-for-rbac --name "sp-github-actions-${PROJECT}" --role "Contributor" --scopes "/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/$RESOURCE_GROUP")

ACR_SERVER=$(az acr show --name "$ACR_NAME" --query loginServer -o tsv)
ACR_USER=$(az acr credential show --name "$ACR_NAME" --query username -o tsv)
ACR_PASS=$(az acr credential show --name "$ACR_NAME" --query "passwords[0].value" -o tsv)

echo ""
echo "════════════════════════════════════════════════════"
echo "  ✅ DONE! ADD THESE AS GITHUB SECRETS:"
echo "  ACR_LOGIN_SERVER    = $ACR_SERVER"
echo "  ACR_USERNAME        = $ACR_USER"
echo "  ACR_PASSWORD        = $ACR_PASS"
echo "  TEST_ENCRYPTION_KEY = $ENCRYPTION_KEY"
echo "  TEST_SECRET_TOKEN   = $SECRET_TOKEN"
echo "  SNYK_TOKEN          = get from https://app.snyk.io/account"
echo "  AZURE_CREDENTIALS   = (JSON below)"
echo "$SP_OUTPUT"
echo "════════════════════════════════════════════════════"
