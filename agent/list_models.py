"""
list_models.py — asks Google directly which models your key can actually
use right now, instead of trusting a hardcoded name in this repo.

Free-tier model availability moves fast and depends on when your API key
was created — the model name in .env.example may already be stale by the
time you read this. Run this first if you get a 404 "model not found" or
"no longer available to new users" error.

Usage:
  python agent/list_models.py
"""
import os

import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
if not API_KEY:
    raise SystemExit("Set GOOGLE_API_KEY in your .env first.")

resp = requests.get(
    "https://generativelanguage.googleapis.com/v1beta/models",
    params={"key": API_KEY},
    timeout=30,
)
resp.raise_for_status()
models = resp.json().get("models", [])

print(f"{'model':45} generateContent?  displayName")
print("-" * 90)
for m in models:
    supports = "generateContent" in m.get("supportedGenerationMethods", [])
    if not supports:
        continue
    name = m["name"].removeprefix("models/")
    print(f"{name:45} {'yes':17} {m.get('displayName', '')}")

print(
    "\nPick a Flash or Flash-Lite model from the list above (Pro models have "
    "much stricter free-tier daily caps) and put it in LLM_MODELS in your .env (comma-separated: first = preferred, the rest are fallbacks)."
)
