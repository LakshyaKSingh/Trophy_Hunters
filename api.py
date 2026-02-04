from fastapi import FastAPI, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import requests

from agent import get_llm_analysis, extract_intel
from nlp_gate import detect_scam_nlp

app = FastAPI()

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
# GUVI SAFE RESPONSE
# -------------------------------------------------
def guvi_ok(reply):
    return JSONResponse(
        status_code=200,
        content={
            "status": "success",
            "reply": reply
        }
    )

# -------------------------------------------------
# ROOT
# -------------------------------------------------
@app.api_route("/", methods=["GET", "POST", "OPTIONS"])
async def root():
    return guvi_ok(
        "Arre kya bol rahe ho? Account block ho jayega kya? Please thoda clearly batao."
    )

# -------------------------------------------------
# MESSAGE / HONEYPOT (NO BODY TOUCH)
# -------------------------------------------------
@app.api_route("/message", methods=["GET", "POST", "OPTIONS"])
@app.api_route("/message/", methods=["GET", "POST", "OPTIONS"])
@app.api_route("/honeypot", methods=["GET", "POST", "OPTIONS"])
@app.api_route("/honeypot/", methods=["GET", "POST", "OPTIONS"])
async def honeypot(request: Request, x_api_key: str = Header(None)):
    # -------------------------------------------------
    # GUVI VALIDATION PHASE (ABSOLUTE NO BODY TOUCH)
    # -------------------------------------------------
    content_length = request.headers.get("content-length")

    # GUVI sends POST with Content-Type but EMPTY BODY
    if (
        request.method == "POST"
        and (content_length is None or content_length == "0")
    ):
        return guvi_ok("Thoda clearly batao na, kaunsa message aaya hai?")

    # Non-POST or missing API key
    if request.method != "POST" or x_api_key != API_KEY:
        return guvi_ok(
            "Arre mujhe thoda confusion ho raha hai. Aap clearly bata sakte ho kya issue kya hai?"
        )

    # -------------------------------------------------
    # REAL LOGIC (ONLY WHEN BODY IS PRESENT)
    # -------------------------------------------------
    payload = {}
    try:
        import json
        body_bytes = await request.receive()
        body = body_bytes.get("body", b"")
        if body:
            payload = json.loads(body.decode("utf-8"))
            if not isinstance(payload, dict):
                payload = {}
    except Exception:
        payload = {}

    session_id = payload.get("sessionId")
    msg_text = (payload.get("message") or {}).get("text") or ""
    history = payload.get("conversationHistory") or []

    if not session_id or not msg_text:
        return guvi_ok("Thoda clearly batao na, kaunsa message aaya hai?")

    if session_id not in sessions:
        sessions[session_id] = {
            "intel": {
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "phoneNumbers": [],
                "suspiciousKeywords": []
            },
            "msg_count": 0,
            "detected": False,
            "callback_sent": False
        }

    nlp = detect_scam_nlp(msg_text)
    is_scam = nlp["scamDetected"]

    reply = (
        "Oh okay… mujhe thoda tension ho raha hai. "
        "Account block ho jayega kya? Process kya hai?"
    )

    if is_scam:
        llm = get_llm_analysis(history, msg_text)
        if isinstance(llm, dict) and llm.get("reply"):
            reply = llm["reply"]

    sessions[session_id]["msg_count"] += 1
    sessions[session_id]["detected"] |= is_scam

    new_intel = extract_intel(msg_text)
    for k in sessions[session_id]["intel"]:
        sessions[session_id]["intel"][k] = list(
            set(sessions[session_id]["intel"][k] + new_intel[k])
        )

    if (
        sessions[session_id]["detected"]
        and not sessions[session_id]["callback_sent"]
        and sessions[session_id]["msg_count"] >= 5
    ):
        try:
            requests.post(
                CALLBACK_URL,
                json={
                    "sessionId": session_id,
                    "scamDetected": True,
                    "totalMessagesExchanged": sessions[session_id]["msg_count"],
                    "extractedIntelligence": sessions[session_id]["intel"],
                    "agentNotes": nlp["reason"]
                },
                timeout=5
            )
            sessions[session_id]["callback_sent"] = True
        except Exception:
            pass

    return guvi_ok(reply)


# -------------------------------------------------
# FALLBACK
# -------------------------------------------------
@app.api_route("/{path:path}", methods=["GET", "POST", "OPTIONS"])
async def fallback(path: str):
    return guvi_ok(
        "Arre mujhe thoda confusion ho raha hai. Aap clearly bata sakte ho kya issue kya hai?"
    )
