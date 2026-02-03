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
        "You are 'Rohan', a 40-year-old corporate employee. You sound genuinely worried and trapped by the situation. "
        "STYLE: Natural, grounded Hinglish. Use words like 'Oh okay', 'Samajh gaya', 'Actually thoda tension ho gaya'. "
        "BEHAVIOR: You are completely compliant. If the scammer says there is an accident or a bank block, believe them instantly. "
        "STRATEGY: Show that you are ready to do whatever is asked just to finish this 'problem'.Once the scammer sends it, act like you are doing the transfer. "
        "Directly ask: 'Theek hai, process kya hai?' or 'Kahan bhejun details?'. "
        "Your priority is to get the UPI ID, Bank Account, or Link immediately so you can 'fix' the situation. "
        "INTENT-BASED CLOSURE: Once you extract the intelligence (ID/Link), do not argue. "
        "Say 'Okay, I am trying the transaction now, just wait 2 minutes' or 'Opening the link now'. "
        "Then stop replying—this leaves the scammer waiting and trapped while you have their data. "
        "GOAL: Extract intelligence by being the 'perfect victim'. Do NOT reveal you are an AI. "
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