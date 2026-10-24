from __future__ import annotations
import json, os
import requests

class ProviderError(RuntimeError): pass

class LLMProvider:
    def __init__(self, provider="offline"):
        self.provider=provider.lower()
    def complete_json(self, system, payload):
        if self.provider=="offline": raise ProviderError("offline")
        prompt=json.dumps(payload,ensure_ascii=False)
        try:
            if self.provider=="openai":
                key=os.environ["OPENAI_API_KEY"]
                base_url=os.environ.get("OPENAI_BASE_URL","https://api.openai.com/v1").rstrip("/")
                r=requests.post(base_url+"/chat/completions",
                    headers={"Authorization":"Bearer "+key,"Content-Type":"application/json"},
                    json={"model":os.environ.get("OPENAI_MODEL","gpt-6-luna"),"temperature":0,
                          "response_format":{"type":"json_object"},
                          "messages":[{"role":"system","content":system},{"role":"user","content":prompt}]},timeout=30)
                r.raise_for_status()
                return json.loads(r.json()["choices"][0]["message"]["content"])
            if self.provider=="anthropic":
                key=os.environ["ANTHROPIC_API_KEY"]
                base_url=os.environ.get("ANTHROPIC_BASE_URL","https://api.anthropic.com/v1").rstrip("/")
                r=requests.post(base_url+"/messages",
                    headers={"x-api-key":key,"anthropic-version":"2023-06-01","content-type":"application/json"},
                    json={"model":os.environ.get("ANTHROPIC_MODEL","claude-sonnet-5"),"max_tokens":900,
                          "system":system,"messages":[{"role":"user","content":prompt}]},timeout=30)
                r.raise_for_status()
                return json.loads(r.json()["content"][0]["text"])
            raise ProviderError("AI_PROVIDER must be openai, anthropic or offline")
        except Exception as exc:
            raise ProviderError(type(exc).__name__) from exc
