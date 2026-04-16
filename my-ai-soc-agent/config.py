"""
Configuration Management
========================
Centralized environment variable configuration using Pydantic BaseSettings.

All sensitive values (API keys, database credentials, endpoints) are loaded
from environment variables with sensible defaults for development.

Usage:
    from config import settings
    groq_api_key = settings.groq_api_key
    nmap_path = settings.nmap_path
    db_url = settings.db_url
    dry_run = settings.dry_run
"""

import os
from pathlib import Path
from typing import Optional

from pydantic import Field, ConfigDict
from pydantic_settings import BaseSettings


def getenv_bool(name: str, default: bool) -> bool:
    """Parse a boolean from environment variables safely."""
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class Settings(BaseSettings):
    """
    Application configuration loaded from environment variables.
    
    Environment variables can be set in a .env file or directly in the shell.
    All paths are resolved relative to the project root.
    """

    model_config = ConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # ─────────────────────────────────────────────────────────────────────
    # LLM & API Configuration
    # ─────────────────────────────────────────────────────────────────────
    
    groq_api_key: str = Field(
        default="",
        description="Groq API key for LLM access. Required for threat analysis.",
        alias="GROQ_API_KEY",
    )
    
    groq_model_main: str = Field(
        default="llama-3.3-70b-versatile",
        description="Main Groq model for threat analysis and response generation.",
        alias="GROQ_MODEL_MAIN",
    )
    
    groq_model_ranker: str = Field(
        default="llama-3.1-8b-instant",
        description="Lightweight Groq model for CVE re-ranking.",
        alias="GROQ_MODEL_RANKER",
    )

    # ─────────────────────────────────────────────────────────────────────
    # Database Configuration (PostgreSQL)
    # ─────────────────────────────────────────────────────────────────────
    
    database_url: str = Field(
        default=os.getenv(
            "DATABASE_URL",
            "postgresql://soc_user:soc_password@localhost:5432/soc_agent",
        ),
        description=(
            "PostgreSQL connection string for LangGraph checkpointer and RAG store. "
            "Format: postgresql://user:password@host:port/dbname"
        ),
        alias="DATABASE_URL",
    )
    
    # Legacy SQLite path (for backwards compatibility / fallback)
    db_url: str = Field(
        default_factory=lambda: os.getenv(
            "DB_URL",
            os.getenv(
                "DATABASE_URL",
                "postgresql://soc_user:soc_password@localhost:5432/soc_agent",
            ),
        ),
        description="Database connection URL. Prefer PostgreSQL URL in DB_URL or DATABASE_URL.",
        alias="DB_URL",
    )
    
    # Legacy ChromaDB path (for backwards compatibility)
    threat_intel_db_path: str = Field(
        default_factory=lambda: os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "vector_db", "chroma_data"
        ),
        description="[DEPRECATED] Path to ChromaDB vector store. Use DATABASE_URL for PostgreSQL pgvector.",
        alias="THREAT_INTEL_DB_PATH",
    )

    # ─────────────────────────────────────────────────────────────────────
    # Scanning & Reconnaissance
    # ─────────────────────────────────────────────────────────────────────
    
    nmap_path: str = Field(
        default=os.getenv("NMAP_PATH", "nmap"),
        description="Path to nmap executable (default: assumes nmap is in PATH).",
        alias="NMAP_PATH",
    )
    
    nmap_timeout: int = Field(
        default=300,
        description="Timeout in seconds for nmap scans.",
        alias="NMAP_TIMEOUT",
    )

    # ─────────────────────────────────────────────────────────────────────
    # Execution & Response Modes
    # ─────────────────────────────────────────────────────────────────────
    
    dry_run: bool = Field(
        default=getenv_bool("DRY_RUN", True),
        description="If True, simulate remediation actions without executing them.",
        alias="DRY_RUN",
    )
    
    log_level: str = Field(
        default="INFO",
        description="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).",
        alias="LOG_LEVEL",
    )

    # ─────────────────────────────────────────────────────────────────────
    # Remote SSH Command Execution
    # ─────────────────────────────────────────────────────────────────────

    target_host: str = Field(
        default="",
        description="Remote host used by the action executor for SSH commands.",
        alias="TARGET_HOST",
    )

    target_user: str = Field(
        default="",
        description="Remote username used by the action executor for SSH commands.",
        alias="TARGET_USER",
    )

    ssh_key_path: str = Field(
        default="",
        description="Path to the SSH private key used by the action executor.",
        alias="SSH_KEY_PATH",
    )

    allow_local_execution: bool = Field(
        default=getenv_bool("ALLOW_LOCAL_EXECUTION", False),
        description="Allow the action executor to run on the local machine when explicitly authorized.",
        alias="ALLOW_LOCAL_EXECUTION",
    )

    # ─────────────────────────────────────────────────────────────────────
    # Firewall API Configuration
    # ─────────────────────────────────────────────────────────────────────
    
    firewall_api_url: str = Field(
        default="http://127.0.0.1:5001",
        description="Base URL for firewall control API.",
        alias="FIREWALL_API_URL",
    )
    
    firewall_block_path: str = Field(
        default="/api/v1/firewall/block-ip",
        description="Endpoint path for blocking IPs on firewall API.",
        alias="FIREWALL_BLOCK_PATH",
    )
    
    firewall_api_token: Optional[str] = Field(
        default=None,
        description="Bearer token for firewall API authentication (optional).",
        alias="FIREWALL_API_TOKEN",
    )
    
    firewall_api_timeout: int = Field(
        default=10,
        description="Timeout in seconds for firewall API calls.",
        alias="FIREWALL_API_TIMEOUT",
    )

    # ─────────────────────────────────────────────────────────────────────
    # EDR API Configuration
    # ─────────────────────────────────────────────────────────────────────
    
    edr_api_url: str = Field(
        default="http://127.0.0.1:5002",
        description="Base URL for EDR (Endpoint Detection & Response) API.",
        alias="EDR_API_URL",
    )
    
    edr_isolate_path: str = Field(
        default="/api/v1/edr/isolate-host",
        description="Endpoint path for host isolation on EDR API.",
        alias="EDR_ISOLATE_PATH",
    )
    
    edr_api_token: Optional[str] = Field(
        default=None,
        description="Bearer token for EDR API authentication (optional).",
        alias="EDR_API_TOKEN",
    )
    
    edr_api_timeout: int = Field(
        default=10,
        description="Timeout in seconds for EDR API calls.",
        alias="EDR_API_TIMEOUT",
    )

    # ─────────────────────────────────────────────────────────────────────
    # Defense API Configuration (Simulated)
    # ─────────────────────────────────────────────────────────────────────
    
    simulated_defense_api_token: Optional[str] = Field(
        default=None,
        description="Bearer token for simulated defense API (optional).",
        alias="SIMULATED_DEFENSE_API_TOKEN",
    )

    # ─────────────────────────────────────────────────────────────────────
    # File & Directory Paths
    # ─────────────────────────────────────────────────────────────────────
    
    incidents_dir: str = Field(
        default_factory=lambda: os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "incidents"
        ),
        description="Directory for storing incident reports and artifacts.",
        alias="INCIDENTS_DIR",
    )
    
    logs_dir: str = Field(
        default_factory=lambda: os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "logs"
        ),
        description="Directory for application logs.",
        alias="LOGS_DIR",
    )

    # ─────────────────────────────────────────────────────────────────────
    # Streamlit Configuration (app.py)
    # ─────────────────────────────────────────────────────────────────────
    
    streamlit_theme: str = Field(
        default="dark",
        description="Streamlit theme (light or dark).",
        alias="STREAMLIT_THEME",
    )
    
    streamlit_max_upload_size: int = Field(
        default=200,
        description="Max file upload size in MB for Streamlit.",
        alias="STREAMLIT_MAX_UPLOAD_SIZE",
    )

    def validate_required_keys(self) -> None:
        """
        Validate that all required keys are set.
        
        Raises:
            ValueError: If any required credential is missing.
        """
        if not self.groq_api_key:
            raise ValueError(
                "GROQ_API_KEY environment variable is required. "
                "Set it in your .env file or export it in your shell."
            )
        
        if not self.nmap_path or not self._nmap_exists():
            raise ValueError(
                f"Nmap not found at '{self.nmap_path}'. "
                "Install nmap or set NMAP_PATH environment variable."
            )

    @staticmethod
    def _nmap_exists() -> bool:
        """Check if nmap is available in PATH."""
        import shutil
        return shutil.which("nmap") is not None
    
    def __init__(self, **data):
        """Initialize settings and validate required keys."""
        super().__init__(**data)
        # Optionally validate on initialization (can be skipped in tests)
        # Uncomment the line below to enforce validation at startup
        # self.validate_required_keys()


# ═════════════════════════════════════════════════════════════════════════
# Global settings instance
# ═════════════════════════════════════════════════════════════════════════

settings = Settings()


# ═════════════════════════════════════════════════════════════════════════
# Module-level helpers for common operations
# ═════════════════════════════════════════════════════════════════════════

def get_checkpoint_db_path() -> str:
    """Get the path to the LangGraph checkpoint database."""
    return settings.db_url


def get_threat_intel_db_path() -> str:
    """Get the path to the threat intelligence vector store."""
    return settings.threat_intel_db_path


def ensure_directories_exist() -> None:
    """Ensure all required directories exist."""
    paths = [
        settings.incidents_dir,
        settings.logs_dir,
        os.path.dirname(settings.threat_intel_db_path),
    ]
    for path in paths:
        if path:
            Path(path).mkdir(parents=True, exist_ok=True)


if __name__ == "__main__":
    # Print all configuration values (mask sensitive data)
    print("\n" + "=" * 70)
    print("Current Configuration")
    print("=" * 70)
    
    for key, value in settings.model_dump().items():
        if any(sensitive in key.lower() for sensitive in ["token", "key", "secret", "password"]):
            display_value = "***REDACTED***" if value else "(not set)"
        else:
            display_value = value
        print(f"{key:.<40} {display_value}")
    
    print("=" * 70 + "\n")
