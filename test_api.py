import requests
import json

# Test the API
API_URL = "http://localhost:5000/honeypot"
API_KEY = "test-key-123"

# Test first message
payload1 = {
    "sessionId": "test-session-123",
    "message": {
        "sender": "scammer",
        "text": "Your bank account will be blocked today. Verify immediately.",
        "timestamp": "2026-01-21T10:15:30Z"
    },
    "conversationHistory": [],
    "metadata": {
        "channel": "SMS",
        "language": "English",
        "locale": "IN"
    }
}

headers = {"x-api-key": API_KEY, "Content-Type": "application/json"}

response1 = requests.post(API_URL, json=payload1, headers=headers)
print("First message response:", response1.json())

# Test follow-up message
payload2 = {
    "sessionId": "test-session-123",
    "message": {
        "sender": "scammer",
        "text": "Share your UPI ID to avoid account suspension.",
        "timestamp": "2026-01-21T10:17:10Z"
    },
    "conversationHistory": [
        {
            "sender": "scammer",
            "text": "Your bank account will be blocked today. Verify immediately.",
            "timestamp": "2026-01-21T10:15:30Z"
        },
        {
            "sender": "user",
            "text": "Why will my account be blocked?",
            "timestamp": "2026-01-21T10:16:10Z"
        }
    ],
    "metadata": {
        "channel": "SMS",
        "language": "English",
        "locale": "IN"
    }
}

response2 = requests.post(API_URL, json=payload2, headers=headers)
print("Follow-up message response:", response2.json())

# Test the /test endpoint
test_response = requests.get("http://localhost:5000/test")
print("Test endpoint response:", test_response.json())
