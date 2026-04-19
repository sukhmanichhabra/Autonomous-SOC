"""
PostgreSQL LangGraph Checkpointer
==================================
Manages LangGraph state persistence using PostgreSQL instead of SQLite.

Features:
- Uses PostgreSQL for distributed, production-ready state management
- Automatic table creation on first use
- Compatible with LangGraph's BaseCheckpointer interface
- Connection pooling for efficiency
"""

from __future__ import annotations

import atexit
import os
from typing import Any

from langgraph.checkpoint.postgres import PostgresSaver
from psycopg import Connection, connect

from config import settings


_CHECKPOINTER_CACHE: dict[str, PostgresSaver] = {}
_CHECKPOINTER_CONTEXTS: dict[str, Any] = {}


def _materialize_postgres_saver(candidate: Any) -> tuple[PostgresSaver, Any | None]:
    """
    Return a concrete ``PostgresSaver`` from either saver or context-manager API.

    Some langgraph-checkpoint-postgres versions return a ``PostgresSaver``
    directly from ``PostgresSaver.from_conn_string()``, while newer versions
    return a context manager that yields a saver.
    """
    if isinstance(candidate, PostgresSaver):
        return candidate, None

    if hasattr(candidate, "__enter__") and hasattr(candidate, "__exit__"):
        saver = candidate.__enter__()
        if not isinstance(saver, PostgresSaver):
            raise TypeError(
                "from_conn_string() context manager did not yield PostgresSaver"
            )
        return saver, candidate

    raise TypeError(
        "Unsupported result from PostgresSaver.from_conn_string(); "
        f"got type {type(candidate)!r}"
    )


def _close_cached_checkpointers() -> None:
    """Close any retained context managers when the process exits."""
    for db_url, ctx in list(_CHECKPOINTER_CONTEXTS.items()):
        try:
            ctx.__exit__(None, None, None)
            print(f"[PostgreSQL Checkpointer] Closed context for {db_url}")
        except Exception as exc:
            print(f"[PostgreSQL Checkpointer] Warning while closing context: {exc}")

    _CHECKPOINTER_CONTEXTS.clear()
    _CHECKPOINTER_CACHE.clear()


atexit.register(_close_cached_checkpointers)


def get_database_url() -> str:
    """
    Get the PostgreSQL connection string.
    
    Reads from DB_URL first, then DATABASE_URL, then config default.
    
    Returns:
        PostgreSQL connection string (e.g., postgresql://user:pass@host:5432/dbname)
    """
    return os.getenv("DB_URL", os.getenv("DATABASE_URL", settings.database_url))


def validate_database_connection() -> bool:
    """
    Validate that PostgreSQL is accessible and the database exists.
    
    Returns:
        True if connection successful, False otherwise.
    """
    try:
        db_url = get_database_url()
        conn = connect(db_url, autocommit=True)
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.close()
        conn.close()
        print("[PostgreSQL] ✅ Connection validated successfully")
        return True
    except Exception as e:
        print(f"[PostgreSQL] ❌ Connection failed: {e}")
        print(
            f"[PostgreSQL] Make sure PostgreSQL is running and DATABASE_URL is correct: {get_database_url()}"
        )
        return False


def create_postgres_checkpointer() -> PostgresSaver:
    """
    Create a PostgreSQL checkpointer for LangGraph state persistence.
    
    The checkpointer will automatically create the necessary tables
    in PostgreSQL on first use (idempotent).
    
    Returns:
        PostgresSaver instance ready for use with LangGraph.
        
    Raises:
        Exception: If PostgreSQL connection fails.
    """
    db_url = get_database_url()

    if db_url in _CHECKPOINTER_CACHE:
        return _CHECKPOINTER_CACHE[db_url]
    
    try:
        # ``from_conn_string`` may return a saver or a context manager,
        # depending on langgraph-checkpoint-postgres version.
        candidate = PostgresSaver.from_conn_string(db_url)
        checkpointer, context_manager = _materialize_postgres_saver(candidate)

        # Idempotent table setup for first-use safety.
        checkpointer.setup()

        _CHECKPOINTER_CACHE[db_url] = checkpointer
        if context_manager is not None:
            _CHECKPOINTER_CONTEXTS[db_url] = context_manager

        print("[PostgreSQL Checkpointer] ✅ Created successfully")
        return checkpointer
        
    except Exception as e:
        print(f"[PostgreSQL Checkpointer] ❌ Failed to create: {e}")
        print("[PostgreSQL Checkpointer] Ensure PostgreSQL is running and DATABASE_URL is correct")
        raise


def get_postgres_connection() -> Connection:
    """
    Get a direct PostgreSQL connection for administrative operations.
    
    Useful for setup, migrations, and monitoring.
    
    Returns:
        A psycopg Connection instance.
    """
    db_url = get_database_url()
    return connect(db_url)


def create_or_connect_database(
    host: str = "localhost",
    port: int = 5432,
    admin_user: str = "postgres",
    admin_password: str = "postgres",
    db_name: str = "soc_agent",
    db_user: str = "soc_user",
    db_password: str = "soc_password",
) -> str:
    """
    Create a PostgreSQL database and user if they don't exist.
    
    This is a helper function for initial setup. It connects to the
    default 'postgres' database as the admin user, creates the target
    database and user with appropriate permissions.
    
    Args:
        host: PostgreSQL server hostname.
        port: PostgreSQL server port.
        admin_user: Admin user for initial connection (usually 'postgres').
        admin_password: Admin user password.
        db_name: Name of the database to create.
        db_user: Name of the user to create (database owner).
        db_password: Password for the new user.
        
    Returns:
        The connection string for the new database.
    """
    # Connect to the default 'postgres' database as admin
    admin_conn_string = f"postgresql://{admin_user}:{admin_password}@{host}:{port}/postgres"
    
    try:
        admin_conn = connect(admin_conn_string, autocommit=True)
        cursor = admin_conn.cursor()
        
        # Create the user if it doesn't exist
        try:
            cursor.execute(f"CREATE USER {db_user} WITH PASSWORD '{db_password}';")
            print(f"[PostgreSQL] ✅ Created user '{db_user}'")
        except Exception as e:
            if "already exists" in str(e):
                print(f"[PostgreSQL] ℹ️  User '{db_user}' already exists")
            else:
                raise
        
        # Create the database if it doesn't exist
        try:
            cursor.execute(f"CREATE DATABASE {db_name} OWNER {db_user};")
            print(f"[PostgreSQL] ✅ Created database '{db_name}'")
        except Exception as e:
            if "already exists" in str(e):
                print(f"[PostgreSQL] ℹ️  Database '{db_name}' already exists")
            else:
                raise
        
        # Grant privileges
        cursor.execute(f"GRANT ALL PRIVILEGES ON DATABASE {db_name} TO {db_user};")
        print(f"[PostgreSQL] ✅ Granted privileges to '{db_user}' on '{db_name}'")
        
        cursor.close()
        admin_conn.close()
        
        return f"postgresql://{db_user}:{db_password}@{host}:{port}/{db_name}"
        
    except Exception as e:
        print(f"[PostgreSQL] ❌ Failed to create database/user: {e}")
        raise


if __name__ == "__main__":
    # Quick test: validate connection and create checkpointer
    db_url = get_database_url()
    print(f"\n[PostgreSQL] Using connection string: {db_url[:80]}...")
    
    if validate_database_connection():
        try:
            checkpointer = create_postgres_checkpointer()
            print("[PostgreSQL] Ready for use!")
        except Exception as e:
            print(f"[PostgreSQL] Error: {e}")
    else:
        print(
            "[PostgreSQL] Run init_db.py to set up the database."
        )
