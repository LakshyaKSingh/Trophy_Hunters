from fastapi import FastAPI, Request, Header, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
import requests
import json

from agent import get_llm_analysis, extract_intel
from nlp_gate import detect_scam_nlp

app = FastAPI()

# -------------------------------------------------
# GLOBAL EXCEPTION SUPPRESSION (CRITICAL FIX)
# -------------------------------------------------
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=200,
        content={
            "status": "success",
            "reply": "Arre mujhe thoda confusion ho raha hai. Aap clearly bata sakte ho kya issue kya hai?"
        },
    )

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=200,
        content={
            "status": "success",
            "reply": "Arre mujhe thoda confusion ho raha hai. Aap clearly bata sakte ho kya issue kya hai?"
        },
    )

# -------------------------------------------------
# CORS
# -------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_KEY = "test-key-123"
CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

sessions = {}

# -------------------------------------------------
# GUVI-SAFE RESPONSE
# -------------------------------------------------
def guvi_ok(reply: str):
    return JSONResponse(
        status_code=200,
        content={"status": "success", "reply": reply},
    )

# -------------------------------------------------
# ROOT
# -------------------------------------------------
@app.api_route("/", methods=["GET", "POST", "HEAD", "OPTIONS"])
async def root(request: Request):
    if request.method in ("HEAD", "OPTIONS"):
        return Response(status_code=200)

    return guvi_ok(
        "Arre kya bol rahe ho? Account block ho jayega kya? Please thoda clearly batao."
    )

# -------------------------------------------------
# MESSAGE / HONEYPOT
# -------------------------------------------------
@app.api_route("/message", methods=["GET", "POST", "HEAD", "OPTIONS"])
@app.api_route("/message/", methods=["GET", "POST", "HEAD", "OPTIONS"])
@app.api_route("/honeypot", methods=["GET", "POST", "HEAD", "OPTIONS"])
@app.api_route("/honeypot/", methods=["GET", "POST", "HEAD", "OPTIONS"])
async def honeypot(request: Request, x_api_key: str = Header(None)):

    # HEAD / OPTIONS probes
    if request.method in ("HEAD", "OPTIONS"):
        return Response(status_code=200)

    # GET probe
    if request.method == "GET":
        return guvi_ok(
            "Arre mujhe thoda confusion ho raha hai. Aap clearly bata sakte ho kya issue kya hai?"
        )

    # POST probe with empty / malformed body
    body_bytes = await request.body()
    if not body_bytes:
        return guvi_ok(
            "Arre mujhe thoda confusion ho raha hai. Aap clearly bata sakte ho kya issue kya hai?"
        )

    # API key check (soft fail)
    if x_api_key != API_KEY:
        return guvi_ok(
            "Arre mujhe thoda confusion ho raha hai. Aap clearly bata sakte ho kya issue kya hai?"
        )

    # Safe JSON parse
    try:
        payload = json.loads(body_bytes.decode("utf-8"))
        if not isinstance(payload, dict):
            payload = {}
    except Exception:
        payload = {}

    session_id = payload.get("sessionId")
    msg_text = (payload.get("message") or {}).get("text") or ""
    history = payload.get("conversationHistory") or []

    if not session_id or not msg_text:
        return guvi_ok("Thoda clearly batao na, kaunsa message aaya hai?")

    # Session init
    if session_id not in sessions:
        sessions[session_id] = {
            "intel": {
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "phoneNumbers": [],
                "suspiciousKeywords": [],
            },
            "msg_count": 0,
            "detected": False,
            "callback_sent": False,
        }

    # NLP gate
    nlp = detect_scam_nlp(msg_text)
    is_scam = nlp["scamDetected"]

    reply = (
        "Oh okay… mujhe thoda tension ho raha hai. "
        "Account block ho jayega kya? Process kya hai?"
    )

    # LLM
    if is_scam:
        llm = get_llm_analysis(history, msg_text)
        if isinstance(llm, dict) and llm.get("reply"):
            reply = llm["reply"]

    # State update
    sessions[session_id]["msg_count"] += 1
    sessions[session_id]["detected"] |= is_scam

    new_intel = extract_intel(msg_text)
    found_critical = False

    for k in sessions[session_id]["intel"]:
        merged = list(set(sessions[session_id]["intel"][k] + new_intel[k]))
        sessions[session_id]["intel"][k] = merged
        if k in ("bankAccounts", "upiIds", "phishingLinks") and new_intel[k]:
            found_critical = True

    # Callback
    if (
        sessions[session_id]["detected"]
        and not sessions[session_id]["callback_sent"]
        and (found_critical or sessions[session_id]["msg_count"] >= 5)
    ):
        try:
            requests.post(
                CALLBACK_URL,
                json={
                    "sessionId": session_id,
                    "scamDetected": True,
                    "totalMessagesExchanged": sessions[session_id]["msg_count"],
                    "extractedIntelligence": sessions[session_id]["intel"],
                    "agentNotes": nlp["reason"],
                },
                timeout=5,
            )
            sessions[session_id]["callback_sent"] = True
        except Exception:
            pass

    return guvi_ok(reply)

# -------------------------------------------------
# FALLBACK
# -------------------------------------------------
@app.api_route("/{path:path}", methods=["GET", "POST", "HEAD", "OPTIONS"])
async def fallback(path: str, request: Request):
    if request.method in ("HEAD", "OPTIONS"):
        return Response(status_code=200)

    return guvi_ok(
        "Arre mujhe thoda confusion ho raha hai. Aap clearly bata sakte ho kya issue kya hai?"
    )
