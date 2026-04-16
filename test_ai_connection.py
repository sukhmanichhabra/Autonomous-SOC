#!/usr/bin/env python3
"""
test_ai_connection.py — Groq Connection Test
=============================================
Loads GROQ_API_KEY from the project .env file, sends a single
cybersecurity-themed prompt via LangChain's ChatGroq, and prints
the AI's response.

Usage:
    python test_ai_connection.py
"""

import sys
import os

# Force unbuffered output (Python 3.14 terminal buffering workaround)
_print = print
def print(*args, **kwargs):
    kwargs.setdefault("flush", True)
    _print(*args, **kwargs)

# Make the project package importable (for the .env path)
PROJECT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "my-ai-soc-agent")
sys.path.insert(0, PROJECT_DIR)

from dotenv import load_dotenv

# Load .env from the project folder
load_dotenv(os.path.join(PROJECT_DIR, ".env"))

api_key = os.getenv("GROQ_API_KEY", "")
model = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

# ---------------------------------------------------------------------------
# Validate the API key
# ---------------------------------------------------------------------------
if not api_key:
    print("❌  GROQ_API_KEY is not set.")
    print("    → Add it to my-ai-soc-agent/.env or export it in your shell.")
    print("    → Get a free key at https://console.groq.com/keys")
    sys.exit(1)

print("=" * 55)
print("  Groq AI Connection Test")
print("=" * 55)
print(f"\n🔑  API key loaded (ends with ...{api_key[-4:]})")
print(f"🤖  Model: {model}")
print(f"📡  Sending test prompt…\n")

# ---------------------------------------------------------------------------
# Send a test message
# ---------------------------------------------------------------------------
try:
    from langchain_groq import ChatGroq
    from langchain_core.messages import HumanMessage

    llm = ChatGroq(model=model, temperature=0, api_key=api_key)
    response = llm.invoke([
        HumanMessage(
            content="Explain the security risk of an open Telnet port in one sentence."
        )
    ])

    print(f"✅  Response: {response.content}")
    print(f"\n{'=' * 55}")
    print("  ✅  Groq connection successful!")
    print(f"{'=' * 55}")

except Exception as exc:
    error_msg = str(exc).lower()

    if "authentication" in error_msg or "invalid api key" in error_msg or "401" in error_msg:
        print(f"❌  Authentication Error: Your Groq API key is invalid or expired.")
        print(f"    → Double-check the key at https://console.groq.com/keys")
        print(f"    Details: {exc}")
    elif "rate" in error_msg or "quota" in error_msg or "429" in error_msg or "limit" in error_msg:
        print(f"❌  Rate Limit / Quota Error: You have exceeded Groq's rate limit.")
        print(f"    → Free-tier keys have per-minute token limits. Wait and retry.")
        print(f"    Details: {exc}")
    elif "model" in error_msg and ("not found" in error_msg or "does not exist" in error_msg):
        print(f"❌  Model Error: The model '{model}' is not available on your Groq account.")
        print(f"    → Try: llama-3.1-70b-versatile or llama-3.1-8b-instant")
        print(f"    Details: {exc}")
    else:
        print(f"❌  Unexpected Error: {exc}")

    sys.exit(1)
