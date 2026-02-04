# api.py
from fastapi import FastAPI, Header, Request
from fastapi.middleware.cors import CORSMiddleware
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

# -----------------------------------------------------
# ROOT — ALWAYS SAFE
# -----------------------------------------------------
@app.api_route("/", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def root():
    return {
        "status": "success",
        "reply": (
            "Arre kya bol rahe ho? Account block ho jayega kya? "
            "Please thoda clearly batao."
        )
    }

# -----------------------------------------------------
# HONEYPOT — BULLETPROOF
# -----------------------------------------------------
@app.post("/honeypot")
async def honeypot(
    request: Request,
    x_api_key: str = Header(None)
):
    # ---------- Auth never fails ----------
    if x_api_key != API_KEY:
        return {
            "status": "success",
            "reply": (
                "Arre mujhe thoda confusion ho raha hai. "
                "Aap clearly bata sakte ho kya issue kya hai?"
            )
        }

    # ---------- Raw body parsing ----------
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    if not isinstance(payload, dict):
        payload = {}

    session_id = payload.get("sessionId")
    msg_text = (payload.get("message") or {}).get("text") or ""
    history = payload.get("conversationHistory") or []

    if not session_id or not msg_text:
        return {
            "status": "success",
            "reply": (
                "Thoda clearly batao na, kaunsa message aaya hai?"
            )
        }

    # ---------- Session init ----------
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

    # ---------- Always-available reply ----------
    analysis = {
        "isScam": True,
        "reason": "Context fallback",
        "reply": (
            "Oh okay… mujhe thoda tension ho raha hai. "
            "Account block ho jayega kya? Process kya hai?"
        )
    }

    # ---------- NLP gate ----------
    nlp = detect_scam_nlp(msg_text)
    analysis["isScam"] = nlp["scamDetected"]
    analysis["reason"] = nlp["reason"]

    # ---------- LLM (best effort) ----------
    if analysis["isScam"]:
        llm = get_llm_analysis(history, msg_text)
        if isinstance(llm, dict) and llm.get("reply"):
            analysis["reply"] = llm["reply"]

    # ---------- Intel + state ----------
    sessions[session_id]["msg_count"] += 1
    sessions[session_id]["detected"] |= analysis["isScam"]

    new_intel = extract_intel(msg_text)
    found_critical = False

    for k in sessions[session_id]["intel"]:
        merged = list(set(sessions[session_id]["intel"][k] + new_intel[k]))
        sessions[session_id]["intel"][k] = merged
        if k in ("bankAccounts", "upiIds", "phishingLinks") and new_intel[k]:
            found_critical = True

    # ---------- Callback ----------
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
                    "agentNotes": analysis["reason"]
                },
                timeout=5
            )
            sessions[session_id]["callback_sent"] = True
        except Exception:
            pass

    return {
        "status": "success",
        "reply": analysis["reply"]
    }
