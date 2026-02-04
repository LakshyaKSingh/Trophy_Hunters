# api.py
from fastapi import FastAPI, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import requests

from agent import get_llm_analysis, extract_intel
from nlp_gate import detect_scam_nlp

app = FastAPI()

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
# SAFE DEFAULT RESPONSE (GUVI-LIKE)
# -------------------------------------------------
def guvi_ok(reply):
    return {
        "status": "success",
        "reply": reply
    }

# -------------------------------------------------
# ROOT — ALWAYS SAFE
# -------------------------------------------------
@app.api_route("/", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def root():
    return guvi_ok(
        "Arre kya bol rahe ho? Account block ho jayega kya? "
        "Please thoda clearly batao."
    )

# -------------------------------------------------
# HONEYPOT — RESTORED BEHAVIOR + HARDENED
# -------------------------------------------------
@app.api_route("/honeypot", methods=["POST", "GET", "OPTIONS"])
@app.api_route("/honeypot/", methods=["POST", "GET", "OPTIONS"])
async def honeypot(request: Request, x_api_key: str = Header(None)):
    # ---- Neutralize GET probes (important) ----
    if request.method != "POST":
        return guvi_ok(
            "Arre mujhe thoda confusion ho raha hai. "
            "Aap clearly bata sakte ho kya issue kya hai?"
        )

    # ---- Auth never blocks ----
    if x_api_key != API_KEY:
        return guvi_ok(
            "Arre mujhe thoda confusion ho raha hai. "
            "Aap clearly bata sakte ho kya issue kya hai?"
        )

    # ---- Body parsing (permissive like old code) ----
    try:
        payload = await request.json()
        if not isinstance(payload, dict):
            payload = {}
    except Exception:
        payload = {}

    session_id = payload.get("sessionId")
    msg_text = (payload.get("message") or {}).get("text") or ""
    history = payload.get("conversationHistory") or []

    if not session_id or not msg_text:
        return guvi_ok(
            "Thoda clearly batao na, kaunsa message aaya hai?"
        )

    # ---- Session init ----
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

    # ---- NLP gate ----
    nlp = detect_scam_nlp(msg_text)
    is_scam = nlp["scamDetected"]

    reply = (
        "Oh okay… mujhe thoda tension ho raha hai. "
        "Account block ho jayega kya? Process kya hai?"
    )

    # ---- LLM best effort ----
    if is_scam:
        llm = get_llm_analysis(history, msg_text)
        if isinstance(llm, dict) and llm.get("reply"):
            reply = llm["reply"]

    # ---- State + intel ----
    sessions[session_id]["msg_count"] += 1
    sessions[session_id]["detected"] |= is_scam

    new_intel = extract_intel(msg_text)
    found_critical = False

    for k in sessions[session_id]["intel"]:
        merged = list(set(sessions[session_id]["intel"][k] + new_intel[k]))
        sessions[session_id]["intel"][k] = merged
        if k in ("bankAccounts", "upiIds", "phishingLinks") and new_intel[k]:
            found_critical = True

    # ---- Callback (unchanged logic) ----
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
                    "agentNotes": nlp["reason"]
                },
                timeout=5
            )
            sessions[session_id]["callback_sent"] = True
        except Exception:
            pass

    return guvi_ok(reply)

# -------------------------------------------------
# FINAL FALLBACK (NEVER HTML)
# -------------------------------------------------
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
async def fallback(path: str, request: Request):
    return guvi_ok(
        "Arre mujhe thoda confusion ho raha hai. "
        "Aap clearly bata sakte ho kya issue kya hai?"
    )
