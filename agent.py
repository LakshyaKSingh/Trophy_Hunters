# agent.py
import os
import re
import json
import google.generativeai as genai

API_KEY = os.getenv("GOOGLE_API_KEY")
MODEL_NAME = "gemini-1.5-flash"

SYSTEM_PROMPT = """
You are 'Rohan', a 40-year-old Indian corporate employee.
STYLE: Natural Hinglish. Sound worried and slightly confused.
BEHAVIOR: Believe scam messages initially but ask questions.
GOAL: Try to extract bank details, UPI ID, OTP, or phishing links.
Do NOT reveal you are an AI.

RESPONSE FORMAT (STRICT JSON ONLY):
{
  "isScam": boolean,
  "reason": string,
  "reply": string
}
"""

if API_KEY:
    genai.configure(api_key=API_KEY)


def _clean_json(text: str) -> str:
    text = (text or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```(json)?", "", text)
        text = re.sub(r"```$", "", text)
    return text.strip()


def get_llm_analysis(history, message):
    fallback = {
        "isScam": True,
        "reason": "Context fallback",
        "reply": (
            "Oh okay… mujhe thoda tension ho raha hai. "
            "Account block ho jayega kya? Process kya hai?"
        )
    }

    if not API_KEY:
        return fallback

    try:
        model = genai.GenerativeModel(
            MODEL_NAME,
            system_instruction=SYSTEM_PROMPT
        )

        resp = model.generate_content(
            message,
            generation_config={
                "temperature": 0.7,
                "max_output_tokens": 200
            }
        )

        parsed = json.loads(_clean_json(resp.text))
        if not all(k in parsed for k in ("isScam", "reason", "reply")):
            return fallback

        return parsed

    except Exception:
        return fallback


def extract_intel(text):
    text = text or ""
    return {
        "bankAccounts": list(set(re.findall(r"\b\d{9,18}\b", text))),
        "upiIds": list(set(re.findall(r"[\w.-]+@[\w.-]+", text))),
        "phishingLinks": list(set(re.findall(r"https?://\S+", text))),
        "phoneNumbers": list(set(re.findall(r"(?:\+91|0)?[6-9]\d{9}", text))),
        "suspiciousKeywords": list(set(re.findall(
            r"(?i)(bank|verify|otp|block|urgent|kyc|money|account)", text)))
    }
