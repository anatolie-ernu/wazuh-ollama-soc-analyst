import asyncio
import logging
import os
import re
import smtplib
import ssl
from email.message import EmailMessage
from urllib.parse import quote
from urllib.parse import urlparse

import httpx

from app.store import claim_notification, mark_notification_sent, retry_notification

logger = logging.getLogger(__name__)
TEAMS_WEBHOOK_URL = os.getenv("TEAMS_WEBHOOK_URL", "").strip()
NTFY_SERVER_URL = os.getenv("NTFY_SERVER_URL", "https://ntfy.sh").strip().rstrip("/")
NTFY_TOPIC = os.getenv("NTFY_TOPIC", "").strip()
NTFY_TOKEN = os.getenv("NTFY_TOKEN", "").strip()
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", "").strip()
SMTP_TO = [item.strip() for item in os.getenv("SMTP_TO", "").split(",") if item.strip()]
NOTIFICATION_MIN_RISK_SCORE = int(os.getenv("NOTIFICATION_MIN_RISK_SCORE", os.getenv("TEAMS_MIN_RISK_SCORE", "70")))


def _https_url(value: str, name: str) -> None:
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError(f"{name} must be an HTTPS URL")


def configured_channels() -> list[str]:
    if not 0 <= NOTIFICATION_MIN_RISK_SCORE <= 100:
        raise ValueError("NOTIFICATION_MIN_RISK_SCORE must be between 0 and 100")
    channels = []
    if TEAMS_WEBHOOK_URL:
        _https_url(TEAMS_WEBHOOK_URL, "TEAMS_WEBHOOK_URL")
        channels.append("teams")
    if NTFY_TOPIC:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", NTFY_TOPIC):
            raise ValueError("NTFY_TOPIC must contain 1-128 letters, digits, '_' or '-' ")
        _https_url(NTFY_SERVER_URL, "NTFY_SERVER_URL")
        channels.append("ntfy")
    elif NTFY_TOKEN:
        raise ValueError("NTFY_TOKEN requires NTFY_TOPIC")
    if SMTP_HOST:
        if not SMTP_FROM or not SMTP_TO:
            raise ValueError("SMTP_FROM and SMTP_TO are required when SMTP_HOST is set")
        if bool(SMTP_USER) != bool(SMTP_PASSWORD):
            raise ValueError("SMTP_USER and SMTP_PASSWORD must be set together")
        if not 1 <= SMTP_PORT <= 65535:
            raise ValueError("SMTP_PORT must be between 1 and 65535")
        channels.append("email")
    elif any((SMTP_USER, SMTP_PASSWORD, SMTP_FROM, SMTP_TO)):
        raise ValueError("SMTP_HOST is required when SMTP settings are provided")
    return channels


def _card_text(value, limit=350) -> str:
    text = str(value or "")
    text = "".join(ch for ch in text if ch.isprintable() or ch in "\t\n")
    text = re.sub(r"https?://\S+", "[URL eliminat]", text)
    text = re.sub(r"[`*_~#>|\[\](){}]", "", text)
    return text.strip()[:limit] or "—"


def _alert_summary(case_id: int, alert: dict, analysis: dict, risk: int) -> dict:
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    data = alert.get("data") or {}
    mitre = rule.get("mitre") or {}
    mitre_ids = mitre.get("id", []) if isinstance(mitre, dict) else []
    if isinstance(mitre_ids, str):
        mitre_ids = [mitre_ids]
    return {
        "case_id": case_id,
        "risk": max(0, min(100, int(risk))),
        "severity": _card_text(analysis.get("severity", "unknown"), 32).upper(),
        "rule_id": _card_text(rule.get("id", "—"), 64),
        "description": _card_text(rule.get("description", "Alertă Wazuh"), 250),
        "agent": _card_text(agent.get("name", "unknown"), 100),
        "srcip": _card_text(data.get("srcip", "—"), 64),
        "summary": _card_text(analysis.get("summary", "Revizuiește alerta în dashboard."), 450),
        "mitre": ", ".join(_card_text(value, 24) for value in mitre_ids[:8] if isinstance(value, str)),
    }


def build_teams_card(case_id: int, alert: dict, analysis: dict, risk: int) -> dict:
    summary = _alert_summary(case_id, alert, analysis, risk)
    facts = [
        {"title": "Risc", "value": f"{summary['risk']}/100"},
        {"title": "Severitate", "value": summary["severity"]},
        {"title": "Regulă Wazuh", "value": summary["rule_id"]},
        {"title": "Agent", "value": summary["agent"]},
        {"title": "IP sursă", "value": summary["srcip"]},
        {"title": "Caz Sentinel", "value": str(case_id)},
    ]
    if summary["mitre"]:
        facts.append({"title": "MITRE ATT&CK", "value": summary["mitre"]})
    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None,
            "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
                "body": [
                    {"type": "TextBlock", "text": f"Sentinel SOC — {summary['severity']}", "weight": "Bolder", "size": "Medium", "wrap": True},
                    {"type": "TextBlock", "text": summary["description"], "wrap": True, "spacing": "Small"},
                    {"type": "FactSet", "facts": facts},
                    {"type": "TextBlock", "text": summary["summary"], "wrap": True, "spacing": "Medium"},
                ]},
        }],
    }


def build_text_notification(case_id: int, alert: dict, analysis: dict, risk: int) -> dict:
    return _alert_summary(case_id, alert, analysis, risk)


def _render_text(payload: dict) -> str:
    return "\n".join([
        f"Alertă SOC — risc {payload['risk']}/100 ({payload['severity']})",
        f"Caz: {payload['case_id']} | Regula Wazuh: {payload['rule_id']}",
        f"Agent: {payload['agent']} | IP sursă: {payload['srcip']}",
        f"Descriere: {payload['description']}",
        f"Analiză AI: {payload['summary']}",
        f"MITRE ATT&CK: {payload['mitre'] or '—'}",
    ])


async def send_teams_card(payload: dict, webhook_url: str | None = None, client: httpx.AsyncClient | None = None) -> None:
    url = webhook_url if webhook_url is not None else TEAMS_WEBHOOK_URL
    _https_url(url, "Teams Workflows webhook")
    if client is not None:
        response = await client.post(url, json=payload, timeout=10)
        response.raise_for_status()
        return
    async with httpx.AsyncClient(timeout=10) as session:
        response = await session.post(url, json=payload)
        response.raise_for_status()


async def send_ntfy(payload: dict, client: httpx.AsyncClient | None = None) -> None:
    _https_url(NTFY_SERVER_URL, "NTFY_SERVER_URL")
    url = f"{NTFY_SERVER_URL}/{quote(NTFY_TOPIC, safe='')}"
    headers = {"Title": f"SOC risk {payload['risk']}/100", "Priority": "urgent" if payload["risk"] >= 90 else "high",
               "Tags": "rotating_light,shield"}
    if NTFY_TOKEN:
        headers["Authorization"] = f"Bearer {NTFY_TOKEN}"
    if client:
        response = await client.post(url, content=_render_text(payload), headers=headers, timeout=10)
        response.raise_for_status()
        return
    async with httpx.AsyncClient(timeout=10) as session:
        response = await session.post(url, content=_render_text(payload), headers=headers)
        response.raise_for_status()


def build_email(payload: dict) -> EmailMessage:
    message = EmailMessage()
    message["Subject"] = f"[Sentinel SOC] Risc {payload['risk']}/100 — cazul {payload['case_id']}"
    message["From"] = SMTP_FROM
    message["To"] = ", ".join(SMTP_TO)
    message.set_content(_render_text(payload))
    return message


def _send_email_sync(payload: dict) -> None:
    message = build_email(payload)
    context = ssl.create_default_context()
    if SMTP_PORT == 465:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=15, context=context) as smtp:
            if SMTP_USER:
                smtp.login(SMTP_USER, SMTP_PASSWORD)
            smtp.send_message(message)
    else:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as smtp:
            smtp.ehlo()
            smtp.starttls(context=context)
            smtp.ehlo()
            if SMTP_USER:
                smtp.login(SMTP_USER, SMTP_PASSWORD)
            smtp.send_message(message)


async def send_notification(channel: str, payload: dict) -> None:
    if channel == "teams":
        await send_teams_card(payload)
    elif channel == "ntfy":
        await send_ntfy(payload)
    elif channel == "email":
        await asyncio.to_thread(_send_email_sync, payload)
    else:
        raise ValueError("unknown notification channel")


async def notification_outbox_worker() -> None:
    while True:
        try:
            notification = await asyncio.to_thread(claim_notification)
        except Exception as exc:
            logger.warning("Notification outbox read failed (%s)", type(exc).__name__)
            await asyncio.sleep(5)
            continue
        if notification is None:
            await asyncio.sleep(2)
            continue
        try:
            await send_notification(notification["channel"], notification["payload"])
            await asyncio.to_thread(mark_notification_sent, notification["id"])
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            try:
                await asyncio.to_thread(retry_notification, notification["id"], notification["attempts"], type(exc).__name__)
            except Exception as store_exc:
                logger.error("Notification retry update failed (%s)", type(store_exc).__name__)
            logger.warning("Notification delivery failed for %s (%s)", notification["channel"], type(exc).__name__)
