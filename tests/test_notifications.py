import asyncio
from email import message_from_bytes

import httpx

from app import notifications


def sample_payload():
    return {
        'case_id': 7, 'risk': 91, 'severity': 'HIGH', 'rule_id': '5710',
        'description': 'SSH login failed', 'agent': 'fw-edge', 'srcip': '192.0.2.5',
        'summary': 'Review repeated failures', 'mitre': 'T1110',
    }


def test_ntfy_publish_uses_auth_and_safe_summary(monkeypatch):
    seen = {}

    def handler(request):
        seen['url'] = str(request.url)
        seen['headers'] = request.headers
        seen['body'] = request.read().decode()
        return httpx.Response(200)

    monkeypatch.setattr(notifications, 'NTFY_SERVER_URL', 'https://ntfy.sh')
    monkeypatch.setattr(notifications, 'NTFY_TOPIC', 'private_topic_123')
    monkeypatch.setattr(notifications, 'NTFY_TOKEN', 'tk_secret')

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await notifications.send_ntfy(sample_payload(), client=client)

    asyncio.run(run())
    assert seen['url'] == 'https://ntfy.sh/private_topic_123'
    assert seen['headers']['authorization'] == 'Bearer tk_secret'
    assert seen['headers']['priority'] == 'urgent'
    assert '192.0.2.5' in seen['body']
    assert 'very sensitive' not in seen['body']


def test_ntfy_topic_is_url_encoded(monkeypatch):
    seen = {}
    monkeypatch.setattr(notifications, 'NTFY_SERVER_URL', 'https://notify.example')
    monkeypatch.setattr(notifications, 'NTFY_TOPIC', 'topic_name-123')

    def handler(request):
        seen['path'] = request.url.path
        return httpx.Response(200)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await notifications.send_ntfy(sample_payload(), client=client)

    asyncio.run(run())
    assert seen['path'] == '/topic_name-123'


def test_email_is_plain_text_and_contains_only_summary(monkeypatch):
    monkeypatch.setattr(notifications, 'SMTP_FROM', 'sentinel@example.test')
    monkeypatch.setattr(notifications, 'SMTP_TO', ['soc@example.test', 'oncall@example.test'])
    message = notifications.build_email(sample_payload())
    parsed = message_from_bytes(message.as_bytes())
    assert parsed['Subject'].startswith('[Sentinel SOC] Risc 91/100')
    assert parsed['To'] == 'soc@example.test, oncall@example.test'
    assert parsed.get_content_type() == 'text/plain'
    assert '192.0.2.5' in parsed.get_payload()
    assert 'full_log' not in parsed.get_payload()


def test_configured_channels_are_disabled_by_default(monkeypatch):
    for key, value in {
        'TEAMS_WEBHOOK_URL': '', 'NTFY_TOPIC': '', 'NTFY_TOKEN': '', 'SMTP_HOST': '',
        'SMTP_USER': '', 'SMTP_PASSWORD': '', 'SMTP_FROM': '', 'SMTP_TO': '',
    }.items():
        monkeypatch.setattr(notifications, key, value)
    assert notifications.configured_channels() == []
