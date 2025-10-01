from openai import OpenAI
import requests
import os

API_KEY = os.getenv("OPENROUTER_API_KEY") or "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"

client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=API_KEY,
)

# ---------- SDK ----------
resp = client.chat.completions.create(
    model="openai/gpt-5-mini",
    messages=[{"role": "user", "content": "just say hi"}],
)
print(resp.choices[0].message.content)
