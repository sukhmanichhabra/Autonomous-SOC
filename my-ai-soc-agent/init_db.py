#!/usr/bin/env python3
"""
Initialize PostgreSQL Database for SOC Agent
==============================================
Creates the PostgreSQL database, enables pgvector extension,
and sets up all necessary tables for the SOC system.

Usage:
    # With default PostgreSQL admin credentials
    python init_db.py

    # With custom connection parameters
    python init_db.py --host localhost --port 5432 \\
        --admin-user postgres --admin-password postgres \\
        --db-name soc_agent --db-user soc_user --db-password soc_password

    # Just validate existing connection
    python init_db.py --validate-only
"""

import argparse
import os
import sys
from pathlib import Path

import psycopg
from psycopg import connect as pg_connect
from psycopg import sql


def create_arg_parser():
    """Create and return argument parser."""
    parser = argparse.ArgumentParser(
        description="Initialize PostgreSQL database for SOC Agent"
    )
    parser.add_argument(
        "--host",
        default=os.getenv("DB_HOST", "localhost"),
        help="PostgreSQL server hostname (default: localhost)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("DB_PORT", "5432")),
        help="PostgreSQL server port (default: 5432)",
    )
    parser.add_argument(
        "--admin-user",
        default=os.getenv("POSTGRES_ADMIN_USER", "postgres"),
        help="Admin user for database creation (default: postgres)",
    )
    parser.add_argument(
        "--admin-password",
        default=os.getenv("POSTGRES_ADMIN_PASSWORD", "postgres"),
        help="Admin user password (default: postgres)",
    )
    parser.add_argument(
        "--db-name",
        default=os.getenv("DB_NAME", "soc_agent"),
        help="Name of database to create (default: soc_agent)",
    )
    parser.add_argument(
        "--db-user",
        default=os.getenv("DB_USER", "soc_user"),
        help="Name of application user (default: soc_user)",
    )
    parser.add_argument(
        "--db-password",
        default=os.getenv("DB_PASSWORD", "soc_password"),
        help="Password for application user (default: soc_password)",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Only validate connection, don't create anything",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Drop and recreate database (DANGEROUS!)",
    )
    return parser


def log(msg: str, level: str = "INFO"):
    """Print a formatted log message."""
    levels = {
        "INFO": "ℹ️ ",
        "SUCCESS": "✅",
        "WARNING": "⚠️ ",
        "ERROR": "❌",
    }
    prefix = levels.get(level, "")
    print(f"[PostgreSQL Init] {prefix} {msg}")


def validate_connection(host: str, port: int, admin_user: str, admin_password: str) -> bool:
    """Validate that PostgreSQL is accessible."""
    try:
        admin_conn_string = (
            f"postgresql://{admin_user}:{admin_password}@{host}:{port}/postgres"
        )
        conn = pg_connect(admin_conn_string, autocommit=True)
        cursor = conn.cursor()
        cursor.execute("SELECT version();")
        version = cursor.fetchone()[0]
        cursor.close()
        conn.close()
        
        log(f"Connected to PostgreSQL: {version.split(',')[0]}", "SUCCESS")
        return True
    except Exception as e:
        log(f"Failed to connect to PostgreSQL: {e}", "ERROR")
        log(
            f"Check that PostgreSQL is running at {host}:{port} "
            f"and credentials are correct",
            "ERROR",
        )
        return False


def create_user_and_database(
    host: str,
    port: int,
    admin_user: str,
    admin_password: str,
    db_name: str,
    db_user: str,
    db_password: str,
    force: bool = False,
) -> bool:
    """Create database and user."""
    admin_conn_string = (
        f"postgresql://{admin_user}:{admin_password}@{host}:{port}/postgres"
    )
    
    try:
        conn = pg_connect(admin_conn_string, autocommit=True)
        cursor = conn.cursor()
        
        # Drop database if --force flag is set
        if force:
            log(f"Dropping database '{db_name}' (--force)...", "WARNING")
            try:
                # Terminate all connections first
                cursor.execute(
                    f"SELECT pg_terminate_backend(pg_stat_activity.pid) "
                    f"FROM pg_stat_activity WHERE datname = '{db_name}' "
                    f"AND pid <> pg_backend_pid();"
                )
                cursor.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(
                    sql.Identifier(db_name)
                ))
                log(f"Dropped database '{db_name}'", "SUCCESS")
            except Exception as e:
                log(f"Failed to drop database: {e}", "WARNING")
        
        # Create user if it doesn't exist
        log(f"Creating user '{db_user}'...", "INFO")
        try:
            cursor.execute(
                sql.SQL("CREATE USER {} WITH PASSWORD {};").format(
                    sql.Identifier(db_user),
                    sql.Literal(db_password),
                )
            )
            log(f"Created user '{db_user}'", "SUCCESS")
        except psycopg.errors.DuplicateObject:
            log(f"User '{db_user}' already exists", "INFO")
            cursor.execute(
                sql.SQL("ALTER USER {} WITH PASSWORD {};").format(
                    sql.Identifier(db_user),
                    sql.Literal(db_password),
                )
            )
            log(f"Updated password for '{db_user}'", "SUCCESS")
        except Exception as e:
            log(f"Failed to create user: {e}", "ERROR")
            return False
        
        # Create database
        log(f"Creating database '{db_name}'...", "INFO")
        try:
            cursor.execute(
                sql.SQL("CREATE DATABASE {} OWNER {};").format(
                    sql.Identifier(db_name),
                    sql.Identifier(db_user),
                )
            )
            log(f"Created database '{db_name}'", "SUCCESS")
        except psycopg.errors.DuplicateDatabase:
            log(f"Database '{db_name}' already exists", "INFO")
        except Exception as e:
            log(f"Failed to create database: {e}", "ERROR")
            return False
        
        # Grant privileges
        log(f"Granting privileges to '{db_user}'...", "INFO")
        cursor.execute(
            sql.SQL("GRANT ALL PRIVILEGES ON DATABASE {} TO {};").format(
                sql.Identifier(db_name),
                sql.Identifier(db_user),
            )
        )
        log(f"Granted privileges", "SUCCESS")
        
        cursor.close()
        conn.close()
        return True
        
    except Exception as e:
        log(f"Database setup failed: {e}", "ERROR")
        return False


def enable_pgvector_extension(
    host: str,
    port: int,
    db_name: str,
    db_user: str,
    db_password: str,
) -> bool:
    """Enable pgvector extension in the database."""
    db_conn_string = (
        f"postgresql://{db_user}:{db_password}@{host}:{port}/{db_name}"
    )
    
    try:
        conn = pg_connect(db_conn_string, autocommit=True)
        cursor = conn.cursor()
        
        log("Enabling pgvector extension...", "INFO")
        cursor.execute("CREATE EXTENSION IF NOT EXISTS vector;")
        
        # Verify extension
        cursor.execute("SELECT extversion FROM pg_extension WHERE extname = 'vector';")
        result = cursor.fetchone()
        
        if result:
            version = result[0]
            log(f"pgvector extension enabled (version {version})", "SUCCESS")
        else:
            log("pgvector extension enabled", "SUCCESS")
        
        cursor.close()
        conn.close()
        return True
        
    except Exception as e:
        log(f"Failed to enable pgvector: {e}", "ERROR")
        log("Make sure pgvector is installed:", "WARNING")
        log("  PostgreSQL 13+: apt install postgresql-13-pgvector", "WARNING")
        log("  Or: https://github.com/pgvector/pgvector#installation", "WARNING")
        return False


def create_langgraph_tables(
    host: str,
    port: int,
    db_name: str,
    db_user: str,
    db_password: str,
) -> bool:
    """Create LangGraph checkpoint tables."""
    db_conn_string = (
        f"postgresql://{db_user}:{db_password}@{host}:{port}/{db_name}"
    )
    
    try:
        log("Creating LangGraph checkpoint tables...", "INFO")
        
        # Import here to avoid failures if postgres isn't installed
        from langgraph.checkpoint.postgres import PostgresSaver
        
        # setup() is the required first-time initialization step for the
        # Postgres checkpointer. It creates the checkpoints and writes tables
        # and applies any needed migrations.
        with PostgresSaver.from_conn_string(db_conn_string) as checkpointer:
            checkpointer.setup()

        log("LangGraph checkpoint tables created", "SUCCESS")
        return True
        
    except Exception as e:
        log(f"Failed to create LangGraph tables: {e}", "ERROR")
        return False


def create_pgvector_tables(
    host: str,
    port: int,
    db_name: str,
    db_user: str,
    db_password: str,
) -> bool:
    """Create pgvector tables for threat intelligence."""
    db_conn_string = (
        f"postgresql://{db_user}:{db_password}@{host}:{port}/{db_name}"
    )
    
    try:
        log("Creating pgvector tables for threat intelligence...", "INFO")
        
        # Import here to avoid failures if langchain isn't fully installed
        from langchain_postgres.vectorstores import PGVector
        from vector_db.pgvector_store import get_embeddings
        
        # Create the vector store - this auto-creates tables
        embeddings = get_embeddings()
        store = PGVector(
            connection_string=db_conn_string,
            embedding_function=embeddings,
            collection_name="threat_intel",
        )
        
        log("pgvector tables created", "SUCCESS")
        return True
        
    except Exception as e:
        log(f"Failed to create pgvector tables: {e}", "WARNING")
        log("This is OK - tables will be created on first use", "INFO")
        return False


def write_env_file(
    host: str,
    port: int,
    db_name: str,
    db_user: str,
    db_password: str,
    env_path: str = ".env",
):
    """Write DATABASE_URL and DB_URL to .env file."""
    try:
        db_url = f"postgresql://{db_user}:{db_password}@{host}:{port}/{db_name}"
        
        # Read existing .env if it exists
        env_content = ""
        if Path(env_path).exists():
            with open(env_path, "r") as f:
                env_content = f.read()
        
        # Update or add DATABASE_URL and DB_URL
        lines = env_content.split("\n")
        updated_lines = []
        found_database_url = False
        found_db_url = False
        
        for line in lines:
            if line.startswith("DATABASE_URL="):
                updated_lines.append(f"DATABASE_URL={db_url}")
                found_database_url = True
            elif line.startswith("DB_URL="):
                updated_lines.append(f"DB_URL={db_url}")
                found_db_url = True
            else:
                updated_lines.append(line)
        
        if not found_database_url:
            updated_lines.append(f"DATABASE_URL={db_url}")
        if not found_db_url:
            updated_lines.append(f"DB_URL={db_url}")
        
        with open(env_path, "w") as f:
            f.write("\n".join(updated_lines))
        
        log(f"Updated {env_path} with DATABASE_URL and DB_URL", "SUCCESS")
    except Exception as e:
        log(f"Failed to write .env file: {e}", "WARNING")


def main():
    """Main setup function."""
    parser = create_arg_parser()
    args = parser.parse_args()
    
    print("\n" + "=" * 70)
    print("PostgreSQL Database Initialization for SOC Agent")
    print("=" * 70 + "\n")
    
    # Validate connection first
    log(f"Connecting to PostgreSQL at {args.host}:{args.port}...", "INFO")
    if not validate_connection(
        args.host,
        args.port,
        args.admin_user,
        args.admin_password,
    ):
        return 1
    
    if args.validate_only:
        log("Connection validated successfully!", "SUCCESS")
        return 0
    
    # Create user and database
    if not create_user_and_database(
        args.host,
        args.port,
        args.admin_user,
        args.admin_password,
        args.db_name,
        args.db_user,
        args.db_password,
        force=args.force,
    ):
        return 1
    
    # Enable pgvector
    if not enable_pgvector_extension(
        args.host,
        args.port,
        args.db_name,
        args.db_user,
        args.db_password,
    ):
        log("Continuing without pgvector (will be needed for vector search)", "WARNING")
    
    # Create tables
    create_langgraph_tables(
        args.host,
        args.port,
        args.db_name,
        args.db_user,
        args.db_password,
    )
    
    create_pgvector_tables(
        args.host,
        args.port,
        args.db_name,
        args.db_user,
        args.db_password,
    )
    
    # Write .env file
    write_env_file(
        args.host,
        args.port,
        args.db_name,
        args.db_user,
        args.db_password,
    )
    
    print("\n" + "=" * 70)
    log("Database initialization complete!", "SUCCESS")
    print("=" * 70)
    
    print("\n📝 Next steps:")
    print(f"  1. DATABASE_URL={args.db_user}:*****@{args.host}:{args.port}/{args.db_name}")
    print(f"  2. pip install -r requirements.txt")
    print(f"  3. streamlit run app.py  (or python main.py)")
    print()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
