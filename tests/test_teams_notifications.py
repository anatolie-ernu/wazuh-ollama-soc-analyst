import asyncio

import httpx

from app.notifications import build_teams_card, send_teams_card


def test_adaptive_card_includes_summary_and_omits_raw_alert():
    alert = {
        'rule': {'id': '100001', 'level': 8, 'description': 'Port scan [details](https://malicious.example)', 'mitre': {'id': ['T1046']}},
        'agent': {'name': 'asa-edge'},
        'data': {'srcip': '192.0.2.10'},
        'full_log': 'very sensitive raw event text',
    }
    payload = build_teams_card(42, alert, {'severity': 'high', 'summary': 'Review source host'}, 82)
    assert payload['type'] == 'message'
    card = payload['attachments'][0]['content']
    assert card['type'] == 'AdaptiveCard'
    text = ' '.join(item.get('text', '') for item in card['body'])
    assert 'high' in text.lower()
    assert 'Review source host' in text
    assert 'malicious.example' not in text
    assert 'very sensitive raw event text' not in str(payload)
    facts = card['body'][2]['facts']
    assert {item['title']: item['value'] for item in facts}['Caz Sentinel'] == '42'
    assert 'T1046' in str(facts)


def test_teams_sender_posts_adaptive_card_over_https():
    seen = {}

    def handler(request):
        seen['url'] = str(request.url)
        seen['payload'] = request.read().decode()
        return httpx.Response(202)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await send_teams_card({'type': 'message'}, 'https://example.test/webhook-secret', client=client)

    asyncio.run(run())
    assert seen['url'] == 'https://example.test/webhook-secret'
    assert '"type":"message"' in seen['payload']


def test_teams_sender_rejects_non_https_webhook():
    async def run():
        await send_teams_card({}, 'http://example.test/webhook')

    try:
        asyncio.run(run())
    except ValueError as exc:
        assert 'HTTPS' in str(exc)
    else:
        raise AssertionError('non-HTTPS Teams webhook should be rejected')
