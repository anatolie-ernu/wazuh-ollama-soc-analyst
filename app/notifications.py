import asyncio
import logging
import os
import re
from urllib.parse import urlparse

import httpx

from app.store import (
    claim_teams_notification,
    mark_teams_notification_sent,
    retry_teams_notification,
)

logger = logging.getLogger(__name__)
TEAMS_WEBHOOK_URL = os.getenv("TEAMS_WEBHOOK_URL", "").strip()
TEAMS_MIN_RISK_SCORE = int(os.getenv("TEAMS_MIN_RISK_SCORE", "70"))


def teams_enabled() -> bool:
    if not TEAMS_WEBHOOK_URL:
        return False
    parsed = urlparse(TEAMS_WEBHOOK_URL)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("TEAMS_WEBHOOK_URL must be an HTTPS URL")
    if not 0 <= TEAMS_MIN_RISK_SCORE <= 100:
        raise ValueError("TEAMS_MIN_RISK_SCORE must be between 0 and 100")
    return True


def _card_text(value, limit=350) -> str:
    text = str(value or "")
    text = "".join(ch for ch in text if ch.isprintable() or ch in "\t\n")
    text = re.sub(r"https?://\S+", "[URL eliminat]", text)
    text = re.sub(r"[`*_~#>|\[\](){}]", "", text)
    return text.strip()[:limit] or "—"


def build_teams_card(case_id: int, alert: dict, analysis: dict, risk: int) -> dict:
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    data = alert.get("data") or {}
    severity = _card_text(analysis.get("severity", "unknown"), 32).upper()
    facts = [
        {"title": "Risc", "value": f"{max(0, min(100, int(risk)))}/100"},
        {"title": "Severitate", "value": severity},
        {"title": "Regulă Wazuh", "value": _card_text(rule.get("id", "—"), 64)},
        {"title": "Agent", "value": _card_text(agent.get("name", "unknown"), 100)},
        {"title": "IP sursă", "value": _card_text(data.get("srcip", "—"), 64)},
        {"title": "Caz Sentinel", "value": str(case_id)},
    ]
    mitre = rule.get("mitre") or {}
    mitre_ids = mitre.get("id", []) if isinstance(mitre, dict) else []
    if isinstance(mitre_ids, str):
        mitre_ids = [mitre_ids]
    mitre_value = ", ".join(_card_text(value, 24) for value in mitre_ids[:8] if isinstance(value, str))
    if mitre_value:
        facts.append({"title": "MITRE ATT&CK", "value": mitre_value})

    description = _card_text(rule.get("description", "Alertă Wazuh"), 250)
    summary = _card_text(analysis.get("summary", "Revizuiește alerta în dashboard."), 450)
    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "contentUrl": None,
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {"type": "TextBlock", "text": f"Sentinel SOC — {severity}", "weight": "Bolder", "size": "Medium", "wrap": True},
                    {"type": "TextBlock", "text": description, "wrap": True, "spacing": "Small"},
                    {"type": "FactSet", "facts": facts},
                    {"type": "TextBlock", "text": summary, "wrap": True, "spacing": "Medium"},
                ],
            },
        }],
    }


async def send_teams_card(payload: dict, webhook_url: str | None = None, client: httpx.AsyncClient | None = None) -> None:
    url = webhook_url if webhook_url is not None else TEAMS_WEBHOOK_URL
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("Teams Workflows webhook must use HTTPS")
    if client is not None:
        response = await client.post(url, json=payload, timeout=10)
        response.raise_for_status()
        return
    async with httpx.AsyncClient(timeout=10) as session:
        response = await session.post(url, json=payload)
        response.raise_for_status()


async def teams_outbox_worker() -> None:
    while True:
        try:
            notification = await asyncio.to_thread(claim_teams_notification)
        except Exception as exc:
            logger.warning("Teams outbox read failed (%s)", type(exc).__name__)
            await asyncio.sleep(5)
            continue
        if notification is None:
            await asyncio.sleep(2)
            continue
        try:
            await send_teams_card(notification["payload"])
            await asyncio.to_thread(mark_teams_notification_sent, notification["id"])
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            try:
                await asyncio.to_thread(retry_teams_notification, notification["id"], notification["attempts"], type(exc).__name__)
            except Exception as store_exc:
                logger.error("Teams notification retry update failed (%s)", type(store_exc).__name__)
            logger.warning("Teams notification delivery failed (%s)", type(exc).__name__)
