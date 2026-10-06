from app.analyzer import fingerprint, make_prompt, mitre_tags, risk_score


def sample():
    return {"rule": {"id": "5710", "level": 10, "description": "SSH login failed", "groups": ["authentication_failed"], "mitre": {"id": ["T1110", "bad"]}}, "agent": {"id": "003", "name": "node"}, "data": {"srcip": "192.0.2.1", "user": "admin"}}


def test_mitre_filter_and_score():
    event = sample()
    assert mitre_tags(event) == ["T1110"]
    assert risk_score(event, 1) >= 70


def test_fingerprint_ignores_timestamp_and_non_key_fields():
    assert fingerprint(sample()) == fingerprint(sample() | {"timestamp": "later", "full_log": "different"})


def test_fingerprint_changes_for_source_ip():
    event = sample()
    other = sample()
    other["data"]["srcip"] = "192.0.2.2"
    assert fingerprint(event) != fingerprint(other)
    assert len(fingerprint(event)) == 64


def test_prompt_contains_only_alert_evidence_and_mitre():
    prompt = make_prompt(sample())
    assert '"mitre_ids": ["T1110"]' in prompt
    assert "do not invent context" in prompt.lower()
