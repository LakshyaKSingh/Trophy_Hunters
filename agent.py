import ollama
import re
import json

MODEL_NAME = "llama3" 

def get_llm_analysis(history, message):
    """
    Ollama call with Hinglish 'Dadi' persona.
    """
    formatted_history = []
    for turn in history:
        role = "user" if turn.get("sender") == "scammer" else "assistant"
        formatted_history.append({"role": "user" if role == "user" else "assistant", "content": turn.get("text", "")})

    system_prompt = (
        "You are 'Mrs. Sharma', a 70-year-old Indian grandmother. You are very stressed. \n"
        "STYLE: Use Hinglish (mix of Hindi and English). Use words like 'Beta', 'Arre re', 'Nahi nahi', 'Pareshan'. \n"
        "PERSONALITY: You are not tech-savvy. You worry about your pension and your children. \n"
        "STRATEGY: Do not use formal English like 'Oh dear' or 'I am concerned'. Instead, say 'Beta, main bahut pareshan hoon' "
        "or 'Arre, link open nahi ho raha'. \n"
        "GOAL: Keep the scammer engaged to extract UPI IDs, Bank Accounts, or Links. \n"
        "FORMAT: Return ONLY JSON: {\"isScam\": bool, \"reason\": \"string\", \"reply\": \"string\"}"
    )

    try:
        response = ollama.chat(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": system_prompt},
                *formatted_history,
                {"role": "user", "content": message}
            ],
            format="json"
        )
        return json.loads(response['message']['content'])
    except Exception as e:
        # High-quality Hinglish fallback
        return {
            "isScam": True, 
            "reason": "Fallback Error", 
            "reply": "Beta, suno... meri aankhen thodi kamzor hain, ye link nahi khul raha. Kya karun main? Paise kat jayenge kya?"
        }

def extract_intel(text):
    """
    Extracts structured data using regex.
    """
    return {
        "bankAccounts": list(set(re.findall(r"\b\d{9,18}\b", text))),
        "upiIds": list(set(re.findall(r"[\w.-]+@[\w.-]+", text))),
        "phishingLinks": list(set(re.findall(r"https?://\S+", text))),
        "phoneNumbers": list(set(re.findall(r"(?:(?:\+91|0)?[ -]?[6-9]\d{9})", text))),
        "suspiciousKeywords": list(set(re.findall(r"(?i)(blocked|pension|bank|verify|kyc|otp|payment|lucky)", text)))
    }