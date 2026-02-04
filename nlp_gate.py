# nlp_gate.py
from typing import Dict, Any

IMPERSONATION = {
    "bank", "customer care", "support",
    "sbi", "hdfc", "icici", "axis",
    "paytm", "phonepe", "gpay",
    "aadhaar", "pan", "government", "govt",
    "income tax", "cyber crime", "police"
}

URGENCY = {
    "urgent", "immediately", "today",
    "now", "within", "right now"
}

THREAT = {
    "blocked", "suspended", "frozen",
    "disabled", "deactivated"
}

ACTION = {
    "verify", "click", "share", "send",
    "pay", "update", "confirm", "kyc", "otp"
}


def detect_scam_nlp(text: str) -> Dict[str, Any]:
    if not text:
        return {
            "scamDetected": False,
            "confidence": 0.0,
            "reason": "Empty message"
        }

    t = text.lower()

    impersonation = any(k in t for k in IMPERSONATION)
    urgency = any(k in t for k in URGENCY)
    threat = any(k in t for k in THREAT)
    action = any(k in t for k in ACTION)

    if impersonation and (urgency or threat or action):
        return {
            "scamDetected": True,
            "confidence": 0.9,
            "reason": "Impersonation with urgency/threat/action"
        }

    if threat and urgency:
        return {
            "scamDetected": True,
            "confidence": 0.8,
            "reason": "Threat-based urgent message"
        }

    if "otp" in t and action:
        return {
            "scamDetected": True,
            "confidence": 0.95,
            "reason": "OTP-based account takeover"
        }

    return {
        "scamDetected": False,
        "confidence": 0.2,
        "reason": "No strong scam indicators"
    }
