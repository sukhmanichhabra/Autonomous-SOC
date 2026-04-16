# Autonomous Cybersecurity SOC — Deployment Configuration Guide

## Overview

Your SOC has been refactored to use centralized environment-based configuration, moving away from hardcoded secrets and local paths. This guide walks you through the setup.

---

## 1. What Changed

### ✅ New Files Created
- **[my-ai-soc-agent/config.py](my-ai-soc-agent/config.py)** — Centralized config using Pydantic BaseSettings
- **[.env.example](.env.example)** — Complete list of all required environment variables with documentation

### ✅ Files Updated
- **[my-ai-soc-agent/main.py](my-ai-soc-agent/main.py)** — Now uses `settings.db_url` from config
- **[app.py](app.py)** — Now imports and uses `settings` for database paths
- **[my-ai-soc-agent/tools/response_automation.py](my-ai-soc-agent/tools/response_automation.py)** — Firewall and EDR API calls now use centralized config
- **[my-ai-soc-agent/vector_db/threat_intel_store.py](my-ai-soc-agent/vector_db/threat_intel_store.py)** — ChromaDB path now uses config
- **[my-ai-soc-agent/incident_io.py](my-ai-soc-agent/incident_io.py)** — Incident directory now uses config
- **[my-ai-soc-agent/requirements.txt](my-ai-soc-agent/requirements.txt)** — Added `pydantic-settings>=2.0.0`

---

## 2. Configuration Structure

### Centralized Config Module

The `config.py` file uses **Pydantic BaseSettings** to manage all environment variables:

```python
from config import settings

# Access any configuration value
groq_key = settings.groq_api_key
db_path = settings.db_url
dry_run = settings.dry_run
nmap_path = settings.nmap_path
firewall_url = settings.firewall_api_url
edr_url = settings.edr_api_url
```

### Configuration Categories

#### LLM & API (REQUIRED)
- `GROQ_API_KEY` — Your Groq API key for LLM access
- `GROQ_MODEL_MAIN` — Main model (default: `llama-3.3-70b-versatile`)
- `GROQ_MODEL_RANKER` — CVE re-ranking model (default: `llama-3.1-8b-instant`)

#### Database
- `DB_URL` — SQLite checkpoint database path
- `THREAT_INTEL_DB_PATH` — ChromaDB threat intelligence store

#### Scanning
- `NMAP_PATH` — Path to nmap executable (default: auto-detect from PATH)
- `NMAP_TIMEOUT` — Timeout for scans in seconds (default: 300)

#### Execution Mode
- `DRY_RUN` — Set to `true` for simulation, `false` for live execution (default: `true`)
- `LOG_LEVEL` — Logging verbosity (default: `INFO`)

#### Firewall API
- `FIREWALL_API_URL` — Base URL (default: `http://127.0.0.1:5001`)
- `FIREWALL_BLOCK_PATH` — Endpoint for blocking IPs
- `FIREWALL_API_TOKEN` — Optional bearer token
- `FIREWALL_API_TIMEOUT` — Request timeout (default: 10s)

#### EDR API
- `EDR_API_URL` — Base URL (default: `http://127.0.0.1:5002`)
- `EDR_ISOLATE_PATH` — Endpoint for host isolation
- `EDR_API_TOKEN` — Optional bearer token
- `EDR_API_TIMEOUT` — Request timeout (default: 10s)

#### Paths & Directories
- `INCIDENTS_DIR` — Reports storage (default: `./my-ai-soc-agent/incidents`)
- `LOGS_DIR` — Application logs (default: `./logs`)

---

## 3. Quick Start

### Step 1: Create Your `.env` File

```bash
cd /Users/sukhmanichhabra/Downloads/Additional_Project
cp .env.example .env
```

### Step 2: Edit `.env` with Your Values

```bash
# Edit .env with your editor
nano .env
# or
vi .env
```

**REQUIRED**: Set your Groq API key:
```env
GROQ_API_KEY=your_actual_groq_api_key_here
```

### Step 3: (Optional) Set Up Firewall & EDR APIs

For production deployments, configure your actual API endpoints:

```env
# Production Firewall
FIREWALL_API_URL=https://firewall.company.com/api
FIREWALL_BLOCK_PATH=/api/v1/firewall/block-ip
FIREWALL_API_TOKEN=your_token_here

# Production EDR
EDR_API_URL=https://edr.company.com/api
EDR_ISOLATE_PATH=/api/v1/edr/isolate-host
EDR_API_TOKEN=your_token_here

# Execute live (use with caution!)
DRY_RUN=false
```

### Step 4: Install Dependencies

```bash
cd my-ai-soc-agent
pip install -r requirements.txt
```

### Step 5: Run the SOC

```bash
# Dashboard (Streamlit)
streamlit run ../app.py

# CLI mode
python main.py --target 192.168.1.1

# Seed threat intelligence DB
python main.py --target 127.0.0.1 --seed-db
```

---

## 4. Environment Variable Loading Order

The configuration is loaded in this priority order (highest to lowest):

1. **Shell Environment Variables** — Set via `export VAR=value` or `.env` file
2. **`.env` File** — In the project root (`/Users/sukhmanichhabra/Downloads/Additional_Project/.env`)
3. **Pydantic Defaults** — Hardcoded defaults in `config.py`

This means you can:
- Use `.env` for development
- Override with environment variables for CI/CD
- Test with different configurations without editing files

### Example: Override via Shell

```bash
# Run with custom API endpoint
export FIREWALL_API_URL=https://custom-firewall.com/api
export DRY_RUN=false

streamlit run app.py
```

---

## 5. Deployment Scenarios

### Development (Safe, Local Simulation)

```env
GROQ_API_KEY=dev_key_here
DRY_RUN=true
FIREWALL_API_URL=http://127.0.0.1:5001
EDR_API_URL=http://127.0.0.1:5002
```

Run with:
```bash
python main.py --target 127.0.0.1
```

### Staging (Tests Against Real APIs)

```env
GROQ_API_KEY=staging_key
DRY_RUN=true  # Still safe!
FIREWALL_API_URL=https://staging-fw.company.com/api
FIREWALL_API_TOKEN=staging_token
EDR_API_URL=https://staging-edr.company.com/api
EDR_API_TOKEN=staging_token
```

### Production (Live Execution)

```env
GROQ_API_KEY=prod_key
DRY_RUN=false  # ⚠️ LIVE EXECUTION
FIREWALL_API_URL=https://firewall.company.com/api
FIREWALL_API_TOKEN=prod_token_with_rotation
EDR_API_URL=https://edr.company.com/api
EDR_API_TOKEN=prod_token_with_rotation
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
```

---

## 6. Key Features of the New Config

### ✅ Type-Safe
All config values are validated by Pydantic:
```python
settings.dry_run  # Guaranteed to be bool
settings.nmap_timeout  # Guaranteed to be int
settings.firewall_api_url  # Guaranteed to be str
```

### ✅ Clear Defaults
Every field has sensible defaults for development and testing.

### ✅ Automatic Directory Creation
Directories are created automatically:
```python
from config import ensure_directories_exist
ensure_directories_exist()  # Creates incidents/, logs/, etc.
```

### ✅ Easy Configuration Introspection
Print all settings (with secrets masked):
```bash
cd my-ai-soc-agent
python config.py
```

Output:
```
======================================================================
Current Configuration
======================================================================
groq_api_key........................... ***REDACTED***
groq_model_main....................... llama-3.3-70b-versatile
firewall_api_url...................... http://127.0.0.1:5001
dry_run.............................. True
...
```

---

## 7. Secrets Management Best Practices

### ⚠️ NEVER commit `.env` to Git

Ensure `.gitignore` includes:
```gitignore
.env
.env.local
.env.*.local
*.key
*.pem
credentials.json
```

### ✅ Use a Secrets Manager for Production

- **AWS Secrets Manager** — `aws secretsmanager get-secret-value`
- **HashiCorp Vault** — `vault kv get secret/soc`
- **Azure Key Vault** — `az keyvault secret show`
- **Kubernetes Secrets** — `kubectl get secret`
- **GitHub Actions** — Use repository secrets and `github.secret.ENV_NAME`

### ✅ Rotate Credentials Regularly

- API keys: Every 90 days
- Database passwords: Every 180 days
- Service account tokens: Every 30 days

### ✅ Principle of Least Privilege

- Grant only the minimum required permissions
- Use separate tokens for each service (firewall ≠ EDR)
- Example Groq API key scopes:
  - Read: False (keys can only inference)
  - Write: False
  - Admin: False

---

## 8. Troubleshooting

### "GROQ_API_KEY not set"

```bash
# Check if set in current shell
echo $GROQ_API_KEY

# If empty, set it
export GROQ_API_KEY=your_key
# or add to .env:
cat >> .env << EOF
GROQ_API_KEY=your_key
EOF
```

### "nmap not found"

```bash
# Check if available
which nmap
# If not, install:
brew install nmap  # macOS
apt install nmap   # Debian/Ubuntu
yum install nmap   # RHEL/CentOS

# Or set explicit path:
export NMAP_PATH=/usr/local/bin/nmap
```

### "Cannot connect to Firewall API"

```bash
# Check endpoint is reachable
curl -v http://127.0.0.1:5001/health

# If local simulation:
cd my-ai-soc-agent
python simulated_defense_api.py --port 5001 --role firewall &
python simulated_defense_api.py --port 5002 --role edr &
```

### Config values not loading

```bash
# Verify .env is in correct location
ls -la .env

# Test config loading in Python
cd my-ai-soc-agent
python -c "from config import settings; print(settings.groq_api_key)"
```

---

## 9. File Structure After Refactoring

```
/Users/sukhmanichhabra/Downloads/Additional_Project/
├── .env                          <- YOUR SECRETS (git-ignored)
├── .env.example                  <- TEMPLATE (committed)
├── .gitignore                    <- Includes .env
├── app.py                        <- Updated: uses config
├── my-ai-soc-agent/
│   ├── config.py                 <- NEW: centralized config
│   ├── main.py                   <- Updated: uses config
│   ├── requirements.txt           <- Updated: pydantic-settings
│   ├── incident_io.py            <- Updated: uses config
│   ├── agents/
│   │   ├── threat_analysis_agent.py
│   │   ├── recon_agent.py
│   │   ├── response_agent.py
│   │   └── ...
│   ├── tools/
│   │   ├── response_automation.py <- Updated: uses config
│   │   ├── action_executor.py
│   │   └── ...
│   ├── vector_db/
│   │   ├── threat_intel_store.py  <- Updated: uses config
│   │   └── chroma_data/
│   └── incidents/                <- Created automatically
└── logs/                         <- Created automatically
```

---

## 10. Example: Complete Deployment Walkthrough

### MacOS Development Setup

```bash
# 1. Navigate to project
cd /Users/sukhmanichhabra/Downloads/Additional_Project

# 2. Create .env
cp .env.example .env

# 3. Edit .env (add your Groq key)
nano .env
# Add: GROQ_API_KEY=gsk_your_key_here

# 4. Install dependencies
cd my-ai-soc-agent
pip install -r requirements.txt

# 5. Verify config loads
python config.py

# 6. Seed threat intelligence database
python main.py --seed-db

# 7. Run first scan
python main.py --target 127.0.0.1

# 8. Launch dashboard
cd ..
streamlit run app.py

# 9. (Optional) Run local defense APIs for testing
python my-ai-soc-agent/simulated_defense_api.py --port 5001 --role firewall &
python my-ai-soc-agent/simulated_defense_api.py --port 5002 --role edr &
```

### Docker Production Setup

Create `Dockerfile`:
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY my-ai-soc-agent/requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "my-ai-soc-agent/main.py", "--target", "${TARGET_IP}"]
```

Build and run:
```bash
docker build -t soc-agent .
docker run --env-file .env.prod \
  -e GROQ_API_KEY=$GROQ_API_KEY \
  -e FIREWALL_API_URL=$FIREWALL_API_URL \
  -e EDR_API_URL=$EDR_API_URL \
  soc-agent
```

---

## 11. Summary of Changes

| Component | Change | Benefit |
|-----------|--------|---------|
| **LLM API Key** | `os.environ["GROQ_API_KEY"]` → `settings.groq_api_key` | Centralized, validated, auditable |
| **Database Paths** | Hardcoded paths → `settings.db_url` | Flexible, environment-specific |
| **Nmap Path** | Hardcoded → `settings.nmap_path` | Works across different OS installations |
| **API Endpoints** | `os.getenv()` calls → `settings.*_api_url` | Single source of truth, easier testing |
| **DRY_RUN Flag** | Inline logic → `settings.dry_run` | Centralized execution mode control |
| **Incident Storage** | Hardcoded paths → `settings.incidents_dir` | Deployable configuration |
| **Log Levels** | Not configurable → `settings.log_level` | Production-ready observability |
| **Directory Creation** | Manual checks → `ensure_directories_exist()` | Automatic setup |

---

## 12. Next Steps

1. **Create `.env`** with your API keys and endpoints
2. **Test locally** with `DRY_RUN=true` before enabling live execution
3. **Set up CI/CD** to inject secrets from your vault (not in source code)
4. **Monitor logs** for any configuration-related errors
5. **Rotate credentials** according to your security policy
6. **Switch to production** endpoints when ready

---

## 13. Support & Documentation

- **Pydantic BaseSettings**: https://docs.pydantic.dev/latest/concepts/pydantic_settings/
- **Groq API**: https://console.groq.com/docs
- **Best Practices**: See [.env.example](.env.example) for detailed field descriptions

---

**🎯 You're ready to deploy!** Your SOC is now production-ready with secure, portable configuration management.
