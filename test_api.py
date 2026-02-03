import requests
import json
import urllib3

# 1. Disable SSL warnings caused by the Fortinet firewall inspection
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 2. Configuration
# Replace with your ngrok URL or "http://localhost:5000/honeypot" for local testing
API_URL = "https://hospitable-goutily-sena.ngrok-free.dev/honeypot"
API_KEY = "test-key-123"

# 3. Headers including the bypass for ngrok's landing page
headers = {
    "x-api-key": API_KEY,
    "Content-Type": "application/json",
    "ngrok-skip-browser-warning": "true" 
}

def run_test():
    print(f"--- Starting Test against {API_URL} ---")

    # TEST 1: Initial Scam Message
    payload1 = {
        "sessionId": "test-session-123",
        "message": {
            "sender": "scammer",
            "text": "Your bank account will be blocked today. Verify immediately via UPI: secure@paytm",
            "timestamp": "2026-01-21T10:15:30Z"
        },
        "conversationHistory": [],
        "metadata": {
            "channel": "SMS",
            "language": "English",
            "locale": "IN"
        }
    }

    try:
        # verify=False is critical to bypass the Fortinet 'ERR_CERT_AUTHORITY_INVALID'
        response1 = requests.post(API_URL, json=payload1, headers=headers, verify=False, timeout=30)
        print("\n[Test 1] First Message Result:")
        print(json.dumps(response1.json(), indent=2))
    except Exception as e:
        print(f"\n[Test 1] Failed: {e}")

    # TEST 2: Follow-up Message
    payload2 = {
        "sessionId": "test-session-123",
        "message": {
            "sender": "scammer",
            "text": "Please share your phone number for verification.",
            "timestamp": "2026-01-21T10:17:10Z"
        },
        "conversationHistory": [
            {
                "sender": "scammer",
                "text": "Your bank account will be blocked today. Verify immediately.",
                "timestamp": "2026-01-21T10:15:30Z"
            }
        ],
        "metadata": { "channel": "SMS" }
    }

    try:
        response2 = requests.post(API_URL, json=payload2, headers=headers, verify=False, timeout=30)
        print("\n[Test 2] Follow-up Message Result:")
        print(json.dumps(response2.json(), indent=2))
    except Exception as e:
        print(f"\n[Test 2] Failed: {e}")

    # TEST 3: Health Check (Optional)
    try:
        # Note: This will only work if you added the /test route to your api.py
        base_url = API_URL.replace("/honeypot", "/test")
        test_resp = requests.get(base_url, headers=headers, verify=False)
        print("\n[Test 3] Server Health Check:")
        print(test_resp.json())
    except:
        print("\n[Test 3] Skip: /test route not defined in api.py")

if __name__ == "__main__":
    run_test()