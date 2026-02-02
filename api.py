from flask import Flask, request, jsonify, send_from_directory
import requests
import os
from agent import get_llm_analysis, extract_intel

app = Flask(__name__)
API_KEY = "test-key-123"
CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

sessions = {}

@app.route("/")
def index():
    return send_from_directory(os.getcwd(), "index.html")

@app.route("/honeypot", methods=["POST"])
def honeypot():
    if request.headers.get("x-api-key") != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json(force=True)
    session_id = data.get("sessionId")
    msg_text = data.get("message", {}).get("text", "")
    history = data.get("conversationHistory", [])

    if session_id not in sessions:
        sessions[session_id] = {
            "intel": {"bankAccounts":[], "upiIds":[], "phishingLinks":[], "phoneNumbers":[], "suspiciousKeywords":[]},
            "msg_count": 0,
            "detected": False,
            "notes": "",
            "callback_sent": False
        }

    # 1. Get Hinglish Analysis
    analysis = get_llm_analysis(history, msg_text)
    
    if analysis.get("isScam"):
        sessions[session_id]["detected"] = True
        sessions[session_id]["notes"] = analysis.get("reason", "Scam detected")

    # 2. Intel Extraction
    new_intel = extract_intel(msg_text)
    has_critical_intel = False
    for key in sessions[session_id]["intel"]:
        combined = list(set(sessions[session_id]["intel"][key] + new_intel[key]))
        sessions[session_id]["intel"][key] = combined
        # Check if we just found a Bank Account, UPI ID, or Link
        if key in ["bankAccounts", "upiIds", "phishingLinks"] and len(new_intel[key]) > 0:
            has_critical_intel = True

    sessions[session_id]["msg_count"] += 1

    # 3. Smart Exit Logic (Requirement Compliance)
    # Callback if: Scam is detected AND (We found critical data OR we hit message limit)
    if sessions[session_id]["detected"] and not sessions[session_id]["callback_sent"]:
        if has_critical_intel or sessions[session_id]["msg_count"] >= 5:
            payload = {
                "sessionId": session_id,
                "scamDetected": True,
                "totalMessagesExchanged": sessions[session_id]["msg_count"],
                "extractedIntelligence": sessions[session_id]["intel"],
                "agentNotes": f"Detected in {sessions[session_id]['msg_count']} turns. Hinglish Persona engagement active."
            }
            try:
                requests.post(CALLBACK_URL, json=payload, timeout=5)
                sessions[session_id]["callback_sent"] = True
            except:
                pass

    return jsonify({
        "status": "success",
        "reply": analysis.get("reply", ""),
        "scamDetected": sessions[session_id]["detected"],
        "totalMessagesExchanged": sessions[session_id]["msg_count"],
        "extractedIntelligence": sessions[session_id]["intel"],
        "agentNotes": sessions[session_id]["notes"]
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)