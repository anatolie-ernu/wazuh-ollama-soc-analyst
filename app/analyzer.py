import hashlib
import json
import os
import re
import httpx

PROVIDER = os.getenv("AI_PROVIDER", "ollama").lower()
MODEL = os.getenv("AI_MODEL", "qwen2.5:3b")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434")


def mitre_tags(alert: dict) -> list[str]:
    value = alert.get("rule", {}).get("mitre", {})
    ids = value.get("id", []) if isinstance(value, dict) else []
    if isinstance(ids, str): ids = [ids]
    return [x for x in ids if isinstance(x, str) and re.fullmatch(r"T\d{4}(?:\.\d{3})?", x)]


def risk_score(alert: dict, count: int = 1) -> int:
    rule = alert.get("rule", {})
    score = min(55, int(rule.get("level", 0) or 0) * 5) + min(20, max(0, count - 1) * 4)
    groups = " ".join(rule.get("groups", [])).lower()
    if any(x in groups for x in ("malware", "rootcheck", "authentication_failed", "attack")): score += 15
    if mitre_tags(alert): score += 10
    return min(score, 100)


def fingerprint(alert: dict) -> str:
    rule, agent, data = alert.get("rule", {}), alert.get("agent", {}), alert.get("data", {})
    value = json.dumps([rule.get("id"), agent.get("id"), rule.get("description"), data.get("srcip"), data.get("user")], separators=(",", ":"))
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def make_prompt(alert: dict, count: int = 1) -> str:
    rule = alert.get("rule", {})
    evidence = {"rule_id": rule.get("id"), "rule_level": rule.get("level"), "description": rule.get("description"), "groups": rule.get("groups", []), "agent": alert.get("agent", {}), "data": alert.get("data", {}), "occurrences_in_window": count, "mitre_ids": mitre_tags(alert)}
    return ("You are an L1 SOC analyst. Analyze only the supplied JSON evidence; do not invent context. Return ONLY JSON with classification (benign,suspicious,malicious,needs_review), severity (low,medium,high,critical), confidence (0..1), summary (max 400 chars), recommended_action (close_candidate,review,escalate_l2), reasoning (max 500 chars). Escalate uncertainty. This recommendation executes no action. Evidence: " + json.dumps(evidence, ensure_ascii=False))


def _validate(result: dict, fallback: dict) -> dict:
    allowed = {"classification": {"benign", "suspicious", "malicious", "needs_review"}, "severity": {"low", "medium", "high", "critical"}, "recommended_action": {"close_candidate", "review", "escalate_l2"}}
    if not isinstance(result, dict): raise ValueError("invalid model JSON")
    for key, options in allowed.items():
        if result.get(key) not in options: result[key] = fallback[key]
    result["confidence"] = max(0.0, min(1.0, float(result.get("confidence", 0))))
    result["summary"] = str(result.get("summary", fallback["summary"]))[:400]
    result["reasoning"] = str(result.get("reasoning", ""))[:500]
    return result


async def _call_model(prompt: str) -> dict:
    if PROVIDER == "ollama":
        async with httpx.AsyncClient(timeout=120) as client:
            response = await client.post(f"{OLLAMA_BASE_URL}/api/generate", json={"model": MODEL, "prompt": prompt, "stream": False, "format": "json", "options": {"temperature": 0.1}})
            response.raise_for_status()
        return json.loads(response.json()["response"])
    async with httpx.AsyncClient(timeout=90) as client:
        if PROVIDER == "openai":
            key = os.getenv("OPENAI_API_KEY", "")
            if not key: raise RuntimeError("OPENAI_API_KEY missing")
            response = await client.post("https://api.openai.com/v1/chat/completions", headers={"Authorization": f"Bearer {key}"}, json={"model": MODEL, "temperature": 0.1, "response_format": {"type": "json_object"}, "messages": [{"role": "system", "content": "You are a careful SOC L1 analyst. Return only the requested JSON."}, {"role": "user", "content": prompt}]})
            response.raise_for_status()
            return json.loads(response.json()["choices"][0]["message"]["content"])
        if PROVIDER == "anthropic":
            key = os.getenv("ANTHROPIC_API_KEY", "")
            if not key: raise RuntimeError("ANTHROPIC_API_KEY missing")
            response = await client.post("https://api.anthropic.com/v1/messages", headers={"x-api-key": key, "anthropic-version": "2023-06-01"}, json={"model": MODEL, "max_tokens": 700, "temperature": 0.1, "system": "You are a careful SOC L1 analyst. Return only a JSON object with the requested fields." , "messages": [{"role": "user", "content": prompt}]})
            response.raise_for_status()
            content = response.json()["content"][0]["text"]
            return json.loads(content[content.find("{"):content.rfind("}")+1])
        if PROVIDER == "google":
            key = os.getenv("GOOGLE_API_KEY", "")
            if not key: raise RuntimeError("GOOGLE_API_KEY missing")
            response = await client.post(f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent", params={"key": key}, json={"contents": [{"parts": [{"text": prompt}]}], "generationConfig": {"temperature": 0.1, "responseMimeType": "application/json"}})
            response.raise_for_status()
            return json.loads(response.json()["candidates"][0]["content"]["parts"][0]["text"])
    raise ValueError("AI_PROVIDER must be ollama, openai, anthropic, or google")


async def analyze(alert: dict, count: int = 1) -> dict:
    score = risk_score(alert, count)
    fallback = {"classification": "needs_review", "severity": "high" if score >= 70 else "medium" if score >= 35 else "low", "confidence": 0.25, "summary": "AI analysis unavailable; review the event in Wazuh.", "recommended_action": "review", "reasoning": "Deterministic fallback; no automated response was executed."}
    try: return _validate(await _call_model(make_prompt(alert, count)), fallback)
    except Exception: return fallback
