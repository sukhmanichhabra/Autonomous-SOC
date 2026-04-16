#!/usr/bin/env python3
"""
test_openai.py — Quick OpenAI Connection Test
==============================================
Loads OPENAI_API_KEY from the project .env file, sends a single
message via LangChain's ChatOpenAI, and prints the result.

Usage:
    python test_openai.py
"""

import sys
import os

# Force unbuffered output (flush after every print)
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

api_key = os.getenv("OPENAI_API_KEY", "")
model = os.getenv("OPENAI_MODEL", "gpt-4o")

if not api_key:
    print("❌  OPENAI_API_KEY is not set.")
    print("    → Add it to my-ai-soc-agent/.env or export it in your shell.")
    sys.exit(1)

print(f"🔑  API key loaded (ends with ...{api_key[-4:]})")
print(f"🤖  Model: {model}")
print(f"📡  Sending test message…\n")

try:
    from langchain_openai import ChatOpenAI
    from langchain_core.messages import HumanMessage

    llm = ChatOpenAI(model=model, temperature=0, api_key=api_key)
    response = llm.invoke([
        HumanMessage(content="Respond with the word SUCCESS if you can read this.")
    ])

    print(f"✅  Response: {response.content}")

except Exception as exc:
    error_msg = str(exc).lower()

    if "authentication" in error_msg or "invalid api key" in error_msg or "401" in error_msg:
        print(f"❌  Authentication Error: Your API key is invalid or expired.")
        print(f"    Details: {exc}")
    elif "billing" in error_msg or "quota" in error_msg or "429" in error_msg or "insufficient" in error_msg:
        print(f"❌  Billing / Quota Error: Your account may have run out of credits.")
        print(f"    Details: {exc}")
    elif "model" in error_msg and ("not found" in error_msg or "does not exist" in error_msg):
        print(f"❌  Model Error: The model '{model}' is not available on your account.")
        print(f"    Details: {exc}")
    else:
        print(f"❌  Unexpected Error: {exc}")

    sys.exit(1)
brew install nmap