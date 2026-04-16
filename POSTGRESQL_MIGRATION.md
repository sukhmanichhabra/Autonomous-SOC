# PostgreSQL Migration Guide

## Overview

Your SOC system has been refactored to use **PostgreSQL** with **pgvector** for production-ready deployment, replacing SQLite and ChromaDB.

### ✅ What Changed

| Component | Before | After |
|-----------|--------|-------|
| **State Checkpointer** | SQLite (`SqliteSaver`) | PostgreSQL (`PostgresSaver`) |
| **Vector Store (RAG)** | ChromaDB (file-based) | PostgreSQL pgvector (production) |
| **Database URL** | `DB_URL` (file path) | `DATABASE_URL` (connection string) |
| **Threat Intel** | `threat_intel_store.py` | `pgvector_store.py` |

---

## 📋 Files Created

### 1. **[my-ai-soc-agent/checkpointer.py](my-ai-soc-agent/checkpointer.py)**
PostgreSQL LangGraph checkpointer wrapper
- `create_postgres_checkpointer()` — Creates PostgresSaver instance
- `validate_database_connection()` — Tests PostgreSQL connectivity
- `get_postgres_connection()` — Admin operations
- `create_or_connect_database()` — Helper for database setup

### 2. **[my-ai-soc-agent/vector_db/pgvector_store.py](my-ai-soc-agent/vector_db/pgvector_store.py)**
PostgreSQL pgvector RAG store (replaces ChromaDB)
- Drop-in replacement for `threat_intel_store.py`
- Same public API (`add_threat_intel()`, `query_threats()`, `seed_sample_data()`)
- Uses LangChain's `PGVector` integration
- Supports multiple embedding models (HuggingFace, fallback hash embedding)

### 3. **[my-ai-soc-agent/init_db.py](my-ai-soc-agent/init_db.py)**
Database initialization script
- Creates PostgreSQL database and user
- Enables pgvector extension
- Creates necessary tables for LangGraph and RAG
- Configurable via command-line arguments
- Writes `DATABASE_URL` to `.env`

---

## 🚀 Quick Start

### Step 1: Install PostgreSQL

**macOS (Homebrew):**
```bash
brew install postgresql
brew services start postgresql
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

**Windows:**
Download from https://www.postgresql.org/download/windows/

### Step 2: Install pgvector Extension

**macOS:**
```bash
brew install pgvector
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt install postgresql-14-pgvector  # (replace 14 with your version)
```

**Or build from source:**
```bash
git clone https://github.com/pgvector/pgvector.git
cd pgvector
make
sudo make install
```

### Step 3: Initialize the Database

```bash
cd /Users/sukhmanichhabra/Downloads/Additional_Project
pip install -r my-ai-soc-agent/requirements.txt

# Create database with default settings
python my-ai-soc-agent/init_db.py

# Or with custom parameters
python my-ai-soc-agent/init_db.py \
  --host localhost \
  --port 5432 \
  --db-name soc_agent \
  --db-user soc_user \
  --db-password your_secure_password
```

**Output:**
```
[PostgreSQL Init] ✅ Connected to PostgreSQL: PostgreSQL 15.2 on ...
[PostgreSQL Init] ✅ Created user 'soc_user'
[PostgreSQL Init] ✅ Created database 'soc_agent'
[PostgreSQL Init] ✅ Granted privileges
[PostgreSQL Init] ✅ pgvector extension enabled (version 0.5.0)
[PostgreSQL Init] ✅ LangGraph checkpoint tables created
[PostgreSQL Init] ✅ pgvector tables created
[PostgreSQL Init] ✅ Updated .env with DATABASE_URL
```

### Step 4: Verify `.env` File

Check that `.env` now contains:
```env
DATABASE_URL=postgresql://soc_user:soc_password@localhost:5432/soc_agent
```

### Step 5: Run Your SOC

```bash
# Streamlit dashboard
streamlit run app.py

# CLI mode
cd my-ai-soc-agent
python main.py --target 192.168.1.1

# Seed threat intelligence
python main.py --seed-db
```

---

## 🔌 Configuration

### Environment Variables

**Required:**
- `DATABASE_URL` — PostgreSQL connection string
  ```
  postgresql://user:password@host:port/dbname
  ```

**Optional:**
(All other settings inherit from `.env.example`)

### Connection String Format

```
postgresql://[user[:password]@][host][:port][/dbname][?param=value...]
```

**Examples:**

```env
# Local development
DATABASE_URL=postgresql://soc_user:soc_password@localhost:5432/soc_agent

# Remote PostgreSQL (AWS RDS)
DATABASE_URL=postgresql://soc_user:soc_password@soc-db.xxxxx.us-east-1.rds.amazonaws.com:5432/soc_agent

# With SSL
DATABASE_URL=postgresql://soc_user:soc_password@host:5432/soc_agent?sslmode=require

# Docker Compose
DATABASE_URL=postgresql://soc_user:soc_password@postgres:5432/soc_agent
```

---

## 📊 Architecture

### PostgreSQL vs Previous Setup

```
Old Setup:
┌─────────────────────────────────────┐
│ Application (Python)                │
├─────────┬──────────────────────────┤
│ SQLite  │ ChromaDB                 │
│ :memory │ ./vector_db/chroma_data/ │
└─────────┴──────────────────────────┘
 ❌ Single-file, not scalable
 ❌ Thread-safety issues (SQLite)
 ❌ No built-in vector search optimization

New Setup:
┌──────────────────────────────────────┐
│ Application (Python)                 │
├──────────────────────────────────────┤
│ PostgreSQL (Single Server)           │
├──────────────────┬──────────────────┤
│ LangGraph Tables │ pgvector Tables  │
│ (checkpoints)    │ (threat_intel)   │
└──────────────────┴──────────────────┘
 ✅ Production-ready
 ✅ Distributed/scalable
 ✅ ACID transactions
 ✅ Built-in vector indexing (pgvector)
```

---

## 🔑 Key Differences from ChromaDB

### ThreatIntelStore API (backward compatible)

Both `threat_intel_store.py` (ChromaDB) and `pgvector_store.py` (PostgreSQL) share the same public interface:

```python
store = ThreatIntelStore()
store.add_threat_intel(documents, metadatas, ids)
results = store.query_threats(query, n_results=5)
store.seed_sample_data()
stats = store.get_stats()
```

### Behind the Scenes

| Operation | ChromaDB | pgvector |
|-----------|----------|----------|
| **Storage** | Local files | PostgreSQL database |
| **Embedding** | ONNX or hash | HuggingFace or hash |
| **Scaling** | Limited to single machine | Full database scaling |
| **Backups** | File copies | pg_dump / pg_restore |
| **Replication** | Manual files | PostgreSQL replication |

---

## 🛠️ Troubleshooting

### "ERROR: could not connect to server"

**Causes:**
- PostgreSQL not running
- Wrong hostname/port
- Credentials incorrect

**Solution:**
```bash
# Check if PostgreSQL is running
psql -U postgres -c "SELECT version();"

# Start PostgreSQL if not running
brew services start postgresql  # macOS
sudo systemctl start postgresql  # Linux

# Init database with correct parameters
python my-ai-soc-agent/init_db.py --host localhost --port 5432
```

### "ERROR: pgvector extension not available"

**Cause:** pgvector not installed on PostgreSQL server

**Solution:**
```bash
# macOS
brew install pgvector

# Linux (Ubuntu/Debian) - check your PostgreSQL version
sudo apt install postgresql-14-pgvector  # (14, 15, etc.)

# Or build from source
git clone https://github.com/pgvector/pgvector.git
cd pgvector && make && sudo make install
```

### "ERROR: relation "langgraph_checkpoint" does not exist"

**Cause:** Tables not created yet

**Solution:** Run init_db.py again:
```bash
python my-ai-soc-agent/init_db.py
```

### "psycopg.OperationalError: server closed the connection unexpectedly"

**Cause:** Connection timeout or server restart

**Solution:**
- Check PostgreSQL is still running
- Increase connection timeout in `checkpointer.py`
- Restart the Python application

### Embedding Model Download Failure

If HuggingFace embeddings fail to download:
- The system falls back to hash-based embeddings (demo only)
- For production: Pre-download model:
  ```python
  from sentence_transformers import SentenceTransformer
  model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')
  ```

---

## 📈 Production Deployment Checklist

- [ ] PostgreSQL 13+ installed and running
- [ ] pgvector extension installed
- [ ] Database and user created via `init_db.py`
- [ ] `.env` file has `DATABASE_URL` set correctly
- [ ] Database credentials rotated and stored securely
- [ ] Backups configured (pg_dump on schedule)
- [ ] Connection pooling enabled (optional: pgBouncer)
- [ ] SSL/TLS enabled for remote connections
- [ ] Monitoring setup (query performance, disk space)
- [ ] Tested failover procedure

---

## 🔄 Migrating from ChromaDB

### Migrating Existing Data

If you have existing threat intelligence in ChromaDB:

```python
from vector_db.threat_intel_store import ThreatIntelStore as ChromaStore
from vector_db.pgvector_store import ThreatIntelStore as PGStore

# Read from ChromaDB
chroma_store = ChromaStore()
results = chroma_store.collection.get()  # Get all documents

# Write to pgvector
pg_store = PGStore()
pg_store.add_threat_intel(
    documents=results['documents'],
    metadatas=results['metadatas'],
    ids=results['ids']
)

print(f"Migrated {len(results['ids'])} documents")
```

### Rolling Back (if needed)

The old ChromaDB implementation is still available:
```python
from vector_db.threat_intel_store import ThreatIntelStore  # ChromaDB
# vs
from vector_db.pgvector_store import ThreatIntelStore  # pgvector
```

---

## 📚 Related Documentation

- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [pgvector GitHub](https://github.com/pgvector/pgvector)
- [LangChain PostgreSQL Integration](https://python.langchain.com/docs/integrations/providers/)
- [LangGraph Checkpointer](https://langchain-ai.github.io/langgraph/concepts/persistence/)

---

## 💡 Tips for Production

### Connection Pooling

For high-concurrency deployments, use pgBouncer:

```bash
# Install pgBouncer
brew install pgbouncer

# Configure /etc/pgbouncer/pgbouncer.ini
[databases]
soc_agent = host=localhost port=5432 user=soc_user password=soc_password

# Start pgBouncer
pgbouncer -d /etc/pgbouncer/pgbouncer.ini

# Update DATABASE_URL to point to pgBouncer
DATABASE_URL=postgresql://soc_user:soc_password@localhost:6432/soc_agent
```

### Monitoring

Key PostgreSQL metrics to monitor:

```sql
-- Check active connections
SELECT datname, count(*) FROM pg_stat_activity GROUP BY datname;

-- Check table size
SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) 
FROM pg_tables ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- Check slow queries
SELECT query, calls, mean_exec_time FROM pg_stat_statements 
ORDER BY mean_exec_time DESC LIMIT 10;
```

### Backups

```bash
# Full backup
pg_dump -U soc_user -h localhost soc_agent > soc_agent-$(date +%Y%m%d).sql

# Restore
psql -U soc_user -h localhost soc_agent < soc_agent-20240101.sql

# Compressed backup (recommended)
pg_dump -U soc_user -h localhost soc_agent | gzip > soc_agent-$(date +%Y%m%d).sql.gz
```

---

**🎉 Your SOC is now PostgreSQL-ready for production!**
