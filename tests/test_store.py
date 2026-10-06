from app.store import _serialize


def test_serialize_mariadb_row():
    from datetime import datetime
    row = {"id": 5, "first_seen": datetime(2026, 1, 1), "last_seen": datetime(2026, 1, 1), "alert_count": 2,
           "alert_json": '{"rule": {"id": "1"}}', "ai_json": '{"classification":"benign"}', "analyst_note": "", "status": "open"}
    result = _serialize(row)
    assert result["count"] == 2
    assert result["alert"]["rule"]["id"] == "1"
    assert result["analysis"]["classification"] == "benign"
