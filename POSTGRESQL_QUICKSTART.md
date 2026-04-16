# PostgreSQL Migration — Quick Reference

## 🚀 30-Second Setup

```bash
# 1. Install PostgreSQL & pgvector
brew install postgresql pgvector  # macOS
# OR
sudo apt install postgresql postgresql-contrib postgresql-14-pgvector  # Linux

# 2. Start PostgreSQL
brew services start postgresql  # macOS
sudo systemctl start postgresql  # Linux

# 3. Initialize database (one command!)
python my-ai-soc-agent/init_db.py

# 4. Run your SOC
streamlit run app.py
```

That's it! Your `.env` will automatically be updated with the PostgreSQL connection string.

---

## 📝 What's New

### Updated Files
- **[config.py](my-ai-soc-agent/config.py)** — Added `DATABASE_URL` field
- **[app.py](app.py)** — Uses `PostgresSaver` instead of `SqliteSaver`
- **[main.py](my-ai-soc-agent/main.py)** — Uses `pgvector_store` instead of `threat_intel_store`
- **[requirements.txt](my-ai-soc-agent/requirements.txt)** — Added `langchain-postgres`, `psycopg`, `pgvector`
- **[.env.example](.env.example)** — Updated with `DATABASE_URL` example

### New Files
- **[checkpointer.py](my-ai-soc-agent/checkpointer.py)** — PostgreSQL checkpointer wrapper
- **[pgvector_store.py](my-ai-soc-agent/vector_db/pgvector_store.py)** — Production RAG store using pgvector
- **[init_db.py](my-ai-soc-agent/init_db.py)** — Database initialization script

---

## 🔧 Environment Variable

### Before (SQLite & ChromaDB)
```env
DB_URL=./my-ai-soc-agent/checkpoints.sqlite
THREAT_INTEL_DB_PATH=./my-ai-soc-agent/vector_db/chroma_data
```

### After (PostgreSQL)
```env
DATABASE_URL=postgresql://soc_user:soc_password@localhost:5432/soc_agent
```

---

## ✅ Verification

**Test PostgreSQL connection:**
```bash
python -c "from checkpointer import validate_database_connection; validate_database_connection()"
```

**Expected output:**
```
[PostgreSQL] ✅ Connection validated successfully
```

---

## 🔑 Key Improvements

| Aspect | SQLite/ChromaDB | PostgreSQL pgvector |
|--------|---|---|
| **Scalability** | Limited to single machine | Full database scaling |
| **Concurrency** | Thread-safety issues | Full ACID transactions |
| **Vector Search** | No optimization | pgvector with indexing |
| **Backups** | Manual file copies | Enterprise backup tools |
| **Replication** | Manual sync | Native PostgreSQL replication |
| **Production Ready** | ❌ | ✅ |

---

## 🆘 Common Issues

### PostgreSQL not found?
```bash
brew install postgresql  # macOS
sudo apt install postgresql postgresql-contrib  # Linux
```

### pgvector extension not found?
```bash
# Check if installed
psql -c "CREATE EXTENSION vector;"

# Install if needed
brew install pgvector  # macOS
# Linux: depends on your version, check PostgreSQL documentation
```

### Need to reset the database?
```bash
python my-ai-soc-agent/init_db.py --force
```

### Using remote PostgreSQL (AWS RDS, Azure)?
```env
DATABASE_URL=postgresql://user:password@your-db.region.rds.amazonaws.com:5432/soc_agent
```

---

## 📚 Full Documentation

See **[POSTGRESQL_MIGRATION.md](POSTGRESQL_MIGRATION.md)** for:
- Detailed setup instructions
- Troubleshooting guide
- Production deployment checklist
- Migration from ChromaDB
- Monitoring and backups
- Connection pooling setup

---

**Ready?** Run `python my-ai-soc-agent/init_db.py` and start using PostgreSQL!
