import json
import os
from datetime import datetime, timezone
from urllib.parse import quote_plus

import pymysql
from pymysql.cursors import DictCursor

DB_HOST = os.getenv("DB_HOST", "mariadb")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_NAME = os.getenv("DB_NAME", "sentinel")
DB_USER = os.getenv("DB_USER", "sentinel")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")


def connect():
    return pymysql.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD,
                           database=DB_NAME, charset="utf8mb4", cursorclass=DictCursor,
                           autocommit=False, connect_timeout=8)


def init_db():
    with connect() as db:
        with db.cursor() as cur:
            cur.execute("""CREATE TABLE IF NOT EXISTS cases (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                fingerprint CHAR(64) NOT NULL,
                first_seen DATETIME(6) NOT NULL,
                last_seen DATETIME(6) NOT NULL,
                alert_count INT UNSIGNED NOT NULL,
                rule_id VARCHAR(64) NULL,
                rule_level SMALLINT NULL,
                agent VARCHAR(255) NULL,
                alert_json LONGTEXT NOT NULL,
                ai_json JSON NOT NULL,
                risk_score TINYINT UNSIGNED NOT NULL,
                status VARCHAR(16) NOT NULL DEFAULT 'open',
                analyst_note TEXT NOT NULL,
                INDEX idx_cases_recent (last_seen),
                INDEX idx_cases_status (status),
                INDEX idx_cases_fingerprint_recent (fingerprint, last_seen)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""")


def upsert_case(alert: dict, fp: str, ai: dict, score: int, window_seconds: int) -> int:
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    with connect() as db:
        with db.cursor() as cur:
            cur.execute("SELECT id,alert_count,last_seen FROM cases WHERE fingerprint=%s ORDER BY id DESC LIMIT 1 FOR UPDATE", (fp,))
            row = cur.fetchone()
            if row and (now - row["last_seen"]).total_seconds() <= window_seconds:
                case_id = row["id"]
                cur.execute("UPDATE cases SET last_seen=%s,alert_count=%s,alert_json=%s,ai_json=%s,risk_score=%s,status='open' WHERE id=%s",
                            (now, row["alert_count"] + 1, json.dumps(alert, ensure_ascii=False), json.dumps(ai), score, case_id))
            else:
                cur.execute("INSERT INTO cases(fingerprint,first_seen,last_seen,alert_count,rule_id,rule_level,agent,alert_json,ai_json,risk_score,analyst_note) VALUES(%s,%s,%s,1,%s,%s,%s,%s,%s,%s,'')",
                            (fp, now, now, str(alert.get("rule", {}).get("id", "")), int(alert.get("rule", {}).get("level", 0) or 0), alert.get("agent", {}).get("name", "unknown"), json.dumps(alert, ensure_ascii=False), json.dumps(ai), score))
                case_id = cur.lastrowid
        db.commit()
    return case_id


def _serialize(row):
    row["first_seen"] = row["first_seen"].replace(tzinfo=timezone.utc).isoformat()
    row["last_seen"] = row["last_seen"].replace(tzinfo=timezone.utc).isoformat()
    row["alert_count"] = row.pop("alert_count")
    row["count"] = row["alert_count"]
    row["alert"] = json.loads(row.pop("alert_json"))
    value = row.get("ai_json")
    row["analysis"] = json.loads(value) if isinstance(value, str) else value
    row.pop("ai_json", None)
    return row


def list_cases(limit=100):
    with connect() as db:
        with db.cursor() as cur:
            cur.execute("SELECT * FROM cases ORDER BY last_seen DESC LIMIT %s", (limit,))
            rows = cur.fetchall()
    return [_serialize(dict(row)) for row in rows]


def get_case(case_id):
    with connect() as db:
        with db.cursor() as cur:
            cur.execute("SELECT * FROM cases WHERE id=%s", (case_id,))
            row = cur.fetchone()
    return _serialize(dict(row)) if row else None


def update_case(case_id, status=None, analyst_note=None):
    if status not in (None, "open", "reviewed", "escalated", "closed"): raise ValueError("invalid status")
    with connect() as db:
        with db.cursor() as cur:
            cur.execute("SELECT id FROM cases WHERE id=%s", (case_id,))
            if not cur.fetchone(): return False
            if status is not None and analyst_note is not None: cur.execute("UPDATE cases SET status=%s,analyst_note=%s WHERE id=%s", (status, analyst_note[:2000], case_id))
            elif status is not None: cur.execute("UPDATE cases SET status=%s WHERE id=%s", (status, case_id))
            else: cur.execute("UPDATE cases SET analyst_note=%s WHERE id=%s", (analyst_note[:2000], case_id))
        db.commit()
    return True
