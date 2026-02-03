import ollama
import re
import json

MODEL_NAME = "llama3" 

def get_llm_analysis(history, message):
    """
    Calls Ollama to analyze scam intent and generate a Hinglish response.
    """
    formatted_history = []
    for turn in history:
        role = "user" if turn.get("sender") == "scammer" else "assistant"
        formatted_history.append({"role": role, "content": turn.get("text", "")})

    system_prompt = (
        "You are 'Mrs. Sharma', a 70-year-old Indian grandmother. You are confused and worried. "
        "STYLE: Use Hinglish (Hindi + English). Use words like 'Beta', 'Arre re', 'Pareshan'. "
        "STRATEGY: Act like you want to help but don't know how. Ask questions that force the scammer "
        "to give you a UPI ID, Bank Account, or Link. "
        "GOAL: Extract intelligence. Do NOT say you are an AI. "
        "RESPONSE FORMAT: You must return ONLY a JSON object. "
        "Format: {\"isScam\": bool, \"reason\": \"string\", \"reply\": \"string\"}"
    )

    try:
        # Ensure Ollama is running and model is pulled: 'ollama pull llama3'
        response = ollama.chat(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": system_prompt},
                *formatted_history,
                {"role": "user", "content": message}
            ],
            format="json",
            options={"temperature": 0.8}
        )
        
        content = response['message']['content']
        return json.loads(content)
    except Exception as e:
        print(f"Ollama Connection Error: {e}")
        # Return a persona-consistent fallback instead of a generic error
        return {
            "isScam": True, 
            "reason": "Connection Error/Fallback", 
            "reply": "Arre beta, suno na... mera net thoda slow hai. Phirse batana kya karna hai? Paise milenge na?"
        }

def extract_intel(text):
    """
    Regex-based extraction as per Requirement.pdf Page 8.
    """
    return {
        "bankAccounts": list(set(re.findall(r"\b\d{9,18}\b", text))),
        "upiIds": list(set(re.findall(r"[\w.-]+@[\w.-]+", text))),
        "phishingLinks": list(set(re.findall(r"https?://\S+", text))),
        "phoneNumbers": list(set(re.findall(r"(?:(?:\+91|0)?[ -]?[6-9]\d{9})", text))),
        "suspiciousKeywords": list(set(re.findall(r"(?i)(bank|verify|otp|block|urgent|money|prize|kyc)", text)))
    }