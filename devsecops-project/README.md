# DevSecOps Lifecycle for Privacy-Preserving Applications
> **Mridula S (23MIA1082)** · **Fedrick Engels (23MIA1004)**

A complete DevSecOps pipeline implementing automated security gates for a Python application using cryptographic privacy techniques, deployed on **Azure Container Apps** via **GitHub Actions**.

---

## 🏗️ Architecture

```
Developer Push
     │
     ▼
┌─────────────────────────────────────────────────────────┐
│                   GitHub Actions Pipeline               │
│                                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐  │
│  │  SAST    │  │   SCA    │  │   Secrets Detection  │  │
│  │ (Bandit) │  │  (Snyk)  │  │    (TruffleHog)      │  │
│  └────┬─────┘  └────┬─────┘  └──────────┬───────────┘  │
│       │             │                    │              │
│       └─────────────┴────────────────────┘              │
│                          │                              │
│                    ┌─────▼──────┐                       │
│                    │ Unit Tests │                       │
│                    └─────┬──────┘                       │
│                          │                              │
│                    ┌─────▼──────┐                       │
│                    │Docker Build│                       │
│                    │  & Push    │ ──► Azure ACR         │
│                    └─────┬──────┘                       │
│                          │                              │
│                    ┌─────▼──────┐                       │
│                    │Image Scan  │                       │
│                    │  (Trivy)   │                       │
│                    └─────┬──────┘                       │
└──────────────────────────┼──────────────────────────────┘
                           │
                    ┌──────▼──────────────────────────┐
                    │        Azure Cloud              │
                    │  ┌──────────────────────────┐   │
                    │  │  Azure Container Apps    │   │
                    │  │  (Auto-scaling, HTTPS)   │   │
                    │  └──────────────────────────┘   │
                    │  ┌───────────┐ ┌────────────┐   │
                    │  │Key Vault  │ │Log Analytics│   │
                    │  │(Secrets)  │ │(Monitoring) │   │
                    │  └───────────┘ └────────────┘   │
                    └─────────────────────────────────┘
```

---

## 🔐 Security Gates

| Gate | Tool | What it checks | Fails on |
|------|------|----------------|----------|
| SAST | Bandit | Python source code insecure patterns | HIGH severity issues |
| SCA | Snyk | Third-party dependency CVEs | HIGH/CRITICAL CVEs |
| Secrets | TruffleHog | Committed credentials in git history | Any verified secrets |
| Image Scan | Trivy | Container OS-layer vulnerabilities | CRITICAL/HIGH CVEs |

---

## 📁 Project Structure

```
devsecops-project/
├── .github/
│   └── workflows/
│       └── devsecops-pipeline.yml   ← Main CI/CD pipeline
├── app/
│   ├── main.py                      ← Flask app (encryption/decryption)
│   └── requirements.txt             ← Python dependencies
├── tests/
│   └── test_app.py                  ← Unit tests (pytest)
├── terraform/
│   └── main.tf                      ← Azure infrastructure (IaC)
├── scripts/
│   └── setup-azure.sh               ← One-time Azure bootstrap
├── Dockerfile                       ← Hardened multi-stage Docker image
├── .bandit                          ← Bandit SAST configuration
└── README.md
```

---

## 🚀 Quick Start

### Prerequisites
- Azure CLI (`az`) installed and logged in
- Terraform >= 1.7.0
- Docker
- Python 3.12+
- GitHub account + Snyk account (free tier works)

### Step 1 — Fork & Clone
```bash
git clone https://github.com/YOUR_USERNAME/devsecops-privacy-app
cd devsecops-privacy-app
```

### Step 2 — Bootstrap Azure Infrastructure
```bash
chmod +x scripts/setup-azure.sh
./scripts/setup-azure.sh
```
This creates all Azure resources and prints the GitHub Secrets you need.

### Step 3 — Add GitHub Secrets
Go to **Repository → Settings → Secrets → Actions** and add:

| Secret Name | Description |
|-------------|-------------|
| `AZURE_CREDENTIALS` | Service principal JSON (printed by setup script) |
| `ACR_LOGIN_SERVER` | e.g. `acrdevsecops.azurecr.io` |
| `ACR_USERNAME` | ACR admin username |
| `ACR_PASSWORD` | ACR admin password |
| `SNYK_TOKEN` | From https://app.snyk.io/account |
| `TEST_ENCRYPTION_KEY` | Fernet key for CI tests |
| `TEST_SECRET_TOKEN` | HMAC token for CI tests |

### Step 4 — Push and Watch the Pipeline
```bash
git add .
git commit -m "feat: initial devsecops pipeline"
git push origin main
```

Go to **Actions** tab on GitHub to watch all security gates run. ✅

---

## 🧪 Local Testing

```bash
# Install dependencies
pip install -r app/requirements.txt pytest pytest-cov cryptography

# Generate test keys
export ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
export SECRET_TOKEN="local-dev-secret"

# Run tests
pytest tests/ -v --cov=app

# Run app locally
python app/main.py
```

### Test API endpoints
```bash
# Encrypt some data
curl -X POST http://localhost:8080/encrypt \
  -H "Content-Type: application/json" \
  -d '{"data": "sensitive-value-123"}'

# Decrypt it back
curl -X POST http://localhost:8080/decrypt \
  -H "Content-Type: application/json" \
  -d '{"data": "<ciphertext from above>"}'

# Privacy-preserving addition
ENC_A=$(curl -s -X POST http://localhost:8080/encrypt -H "Content-Type: application/json" -d '{"data":"42"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['encrypted'])")
ENC_B=$(curl -s -X POST http://localhost:8080/encrypt -H "Content-Type: application/json" -d '{"data":"8"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['encrypted'])")
curl -X POST http://localhost:8080/compute \
  -H "Content-Type: application/json" \
  -d "{\"enc_a\": \"$ENC_A\", \"enc_b\": \"$ENC_B\"}"
```

---

## 🐳 Docker (Local)

```bash
docker build -t privacy-app .

docker run -p 8080:8080 \
  -e ENCRYPTION_KEY="$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')" \
  -e SECRET_TOKEN="local-test-secret" \
  privacy-app
```

---

## 📊 Security Impact

- **SAST** catches insecure pickle usage, hardcoded passwords, unsafe subprocess calls
- **SCA** prevents use of packages with known CVEs in requirements.txt
- **TruffleHog** eliminates credential leakage in git history
- **Trivy** ensures only patched OS base images reach production
- **Key Vault** ensures secrets never appear in code or environment files

---

## 🔗 References

- [Bandit Documentation](https://bandit.readthedocs.io)
- [Snyk Python Scanning](https://docs.snyk.io/products/snyk-open-source/language-and-package-manager-support/snyk-for-python)
- [TruffleHog GitHub Action](https://github.com/trufflesecurity/trufflehog)
- [Trivy GitHub Action](https://github.com/aquasecurity/trivy-action)
- [Azure Container Apps](https://learn.microsoft.com/en-us/azure/container-apps/)
# DevSecOps Pipeline
