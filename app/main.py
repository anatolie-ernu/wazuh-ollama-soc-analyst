import hmac
import json
import logging
import os
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from app.analyzer import analyze, fingerprint, mitre_tags, risk_score
from app.notifications import NOTIFICATION_MIN_RISK_SCORE, build_teams_card, build_text_notification, configured_channels, notification_outbox_worker
from app.store import enqueue_notification, get_case, init_db, list_cases, update_case, upsert_case

API_KEY = os.getenv("INGEST_API_KEY", "")
WINDOW = int(os.getenv("CORRELATION_WINDOW_SECONDS", "300"))
MAX_BODY = int(os.getenv("MAX_ALERT_BODY_BYTES", "262144"))
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    channels = configured_channels()
    worker = asyncio.create_task(notification_outbox_worker()) if channels else None
    try:
        yield
    finally:
        if worker:
            worker.cancel()
            try:
                await worker
            except asyncio.CancelledError:
                pass

app = FastAPI(title="Sentinel L1 SOC Analyst", version="0.1.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

def valid_key(candidate): return bool(API_KEY and candidate) and hmac.compare_digest(API_KEY, candidate)

@app.get("/healthz")
async def health(): return {"status": "ok"}

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    with open("app/static/index.html", encoding="utf-8") as page: return page.read()

@app.post("/api/v1/alerts", status_code=202)
async def ingest(request: Request, x_api_key: str | None = Header(default=None)):
    if not valid_key(x_api_key): raise HTTPException(status_code=401, detail="invalid_api_key")
    if int(request.headers.get("content-length", "0") or 0) > MAX_BODY: raise HTTPException(status_code=413, detail="alert_too_large")
    raw = await request.body()
    if len(raw) > MAX_BODY: raise HTTPException(status_code=413, detail="alert_too_large")
    try: alert = json.loads(raw)
    except (ValueError, UnicodeDecodeError): raise HTTPException(status_code=400, detail="invalid_json")
    if not isinstance(alert, dict) or not isinstance(alert.get("rule"), dict): raise HTTPException(status_code=422, detail="expected_wazuh_alert_object")
    ai = await analyze(alert)
    score = risk_score(alert)
    case_id, created = upsert_case(alert, fingerprint(alert), ai, score, WINDOW)
    queued_channels = []
    channels = configured_channels()
    if created and score >= NOTIFICATION_MIN_RISK_SCORE:
        for channel in channels:
            try:
                payload = build_teams_card(case_id, alert, ai, score) if channel == "teams" else build_text_notification(case_id, alert, ai, score)
                enqueue_notification(case_id, channel, payload)
                queued_channels.append(channel)
            except Exception as exc:
                logger.warning("Could not queue %s notification (%s)", channel, type(exc).__name__)

    return {"accepted": True, "case_id": case_id, "risk_score": score,
            "notification_queued": queued_channels}

@app.get("/api/v1/cases")
async def cases():
    result = list_cases()
    for item in result: item["mitre"] = mitre_tags(item["alert"])
    return result

@app.get("/api/v1/cases/{case_id}")
async def case_detail(case_id: int):
    result = get_case(case_id)
    if not result: raise HTTPException(status_code=404, detail="case_not_found")
    result["mitre"] = mitre_tags(result["alert"])
    return result

@app.patch("/api/v1/cases/{case_id}")
async def patch_case(case_id: int, request: Request, x_api_key: str | None = Header(default=None)):
    if not valid_key(x_api_key): raise HTTPException(status_code=401, detail="invalid_api_key")
    try:
        body = await request.json()
        if not isinstance(body, dict) or set(body) - {"status", "analyst_note"} or not body: raise ValueError
        if not update_case(case_id, body.get("status"), body.get("analyst_note")): raise HTTPException(status_code=404, detail="case_not_found")
    except ValueError: raise HTTPException(status_code=422, detail="invalid_case_update")
    return {"updated": True, "case_id": case_id}
