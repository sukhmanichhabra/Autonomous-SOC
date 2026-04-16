#!/usr/bin/env python3
"""
Configuration Verification Script
==================================
Validates that the refactored configuration system is working correctly.

Usage:
    cd my-ai-soc-agent
    python verify_config.py
"""

import sys
import os
from pathlib import Path

def check_file_exists(path: str, description: str) -> bool:
    """Check if a file exists and report status."""
    if Path(path).exists():
        print(f"✅ {description}: {path}")
        return True
    else:
        print(f"❌ {description}: {path} NOT FOUND")
        return False

def check_import(module_path: str, description: str) -> bool:
    """Check if a module can be imported."""
    try:
        __import__(module_path)
        print(f"✅ {description}: {module_path}")
        return True
    except ImportError as e:
        print(f"❌ {description}: {module_path} — {e}")
        return False

def main():
    """Run all verification checks."""
    print("\n" + "=" * 70)
    print("Configuration Refactoring Verification")
    print("=" * 70 + "\n")

    all_passed = True

    # Check files exist
    print("📁 Checking files...")
    all_passed &= check_file_exists("config.py", "Config module")
    all_passed &= check_file_exists("../.env.example", ".env.example template")
    all_passed &= check_file_exists("../DEPLOYMENT_CONFIG.md", "Deployment guide")
    all_passed &= check_file_exists("../REFACTORING_SUMMARY.md", "Refactoring summary")
    print()

    # Check imports
    print("📚 Checking imports...")
    all_passed &= check_import("config", "config module")
    all_passed &= check_import("pydantic", "pydantic")
    all_passed &= check_import("pydantic_settings", "pydantic-settings")
    print()

    # Check config loads
    print("⚙️  Checking configuration loading...")
    try:
        from config import settings, ensure_directories_exist
        print(f"✅ Settings object loaded")
        print(f"   - groq_api_key set: {bool(settings.groq_api_key)}")
        print(f"   - db_url: {settings.db_url}")
        print(f"   - dry_run: {settings.dry_run}")
        print(f"   - nmap_path: {settings.nmap_path}")
        print(f"   - firewall_api_url: {settings.firewall_api_url}")
        print(f"   - edr_api_url: {settings.edr_api_url}")
    except Exception as e:
        print(f"❌ Failed to load settings: {e}")
        all_passed = False
    print()

    # Check directory creation
    print("📂 Checking directory creation...")
    try:
        from config import ensure_directories_exist
        ensure_directories_exist()
        
        dirs_to_check = [
            settings.incidents_dir,
            settings.logs_dir,
            os.path.dirname(settings.threat_intel_db_path),
        ]
        
        for dir_path in dirs_to_check:
            if Path(dir_path).exists():
                print(f"✅ Directory exists: {dir_path}")
            else:
                print(f"❌ Directory not created: {dir_path}")
                all_passed = False
    except Exception as e:
        print(f"❌ Failed to create directories: {e}")
        all_passed = False
    print()

    # Check that files import config correctly
    print("🔍 Checking file imports...")
    files_to_check = {
        "main.py": "from config import settings",
        "incident_io.py": "from config import settings",
        "tools/response_automation.py": "from config import settings",
        "vector_db/threat_intel_store.py": "from config import settings",
    }
    
    for file_path, import_str in files_to_check.items():
        full_path = Path(file_path)
        if full_path.exists():
            content = full_path.read_text()
            if import_str in content:
                print(f"✅ {file_path}: Has correct import")
            else:
                print(f"❌ {file_path}: Missing '{import_str}'")
                all_passed = False
        else:
            print(f"⚠️  {file_path}: File not found")
    print()

    # Summary
    print("=" * 70)
    if all_passed:
        print("✅ ALL CHECKS PASSED! Configuration is ready for deployment.")
        return 0
    else:
        print("❌ SOME CHECKS FAILED. Please review the errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
