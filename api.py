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
    # 1. Authentication
    if request.headers.get("x-api-key") != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        data = request.get_json(force=True)
    except:
        return jsonify({"error": "Invalid JSON"}), 400

    session_id = data.get("sessionId")
    msg_text = data.get("message", {}).get("text", "")
    history = data.get("conversationHistory", [])

    if session_id not in sessions:
        sessions[session_id] = {
            "intel": {"bankAccounts":[], "upiIds":[], "phishingLinks":[], "phoneNumbers":[], "suspiciousKeywords":[]},
            "msg_count": 0,
            "detected": False,
            "callback_sent": False
        }

    # 2. Process Analysis
    analysis = get_llm_analysis(history, msg_text)
    if analysis.get("isScam"):
        sessions[session_id]["detected"] = True

    # 3. Intelligence Gathering
    new_intel = extract_intel(msg_text)
    found_critical = False
    
    for key in sessions[session_id]["intel"]:
        # Merge and remove duplicates
        combined = list(set(sessions[session_id]["intel"][key] + new_intel[key]))
        # Check if we just found something new and critical
        if key in ["bankAccounts", "upiIds", "phishingLinks"] and len(new_intel[key]) > 0:
            found_critical = True
        sessions[session_id]["intel"][key] = combined

    sessions[session_id]["msg_count"] += 1

    # 4. Smart Exit / Callback Logic
    # Trigger if (Scam + New Intel found) OR (Scam + 5 messages reached)
    if sessions[session_id]["detected"] and not sessions[session_id]["callback_sent"]:
        if found_critical or sessions[session_id]["msg_count"] >= 5:
            payload = {
                "sessionId": session_id,
                "scamDetected": True,
                "totalMessagesExchanged": sessions[session_id]["msg_count"],
                "extractedIntelligence": sessions[session_id]["intel"],
                "agentNotes": f"Scam confirmed. Persona: Mrs. Sharma. Reason: {analysis.get('reason')}"
            }
            try:
                requests.post(CALLBACK_URL, json=payload, timeout=5)
                sessions[session_id]["callback_sent"] = True
            except Exception as e:
                print(f"Callback Failed: {e}")

    return jsonify({
        "status": "success",
        "reply": analysis.get("reply", ""),
        "scamDetected": sessions[session_id]["detected"],
        "totalMessagesExchanged": sessions[session_id]["msg_count"],
        "extractedIntelligence": sessions[session_id]["intel"],
        "agentNotes": analysis.get("reason", "") if sessions[session_id]["detected"] else ""
    })

if __name__ == "__main__":
    app.run(port=5000, debug=True)