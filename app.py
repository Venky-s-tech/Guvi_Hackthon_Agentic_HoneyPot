from flask import Flask, request, jsonify
import os
import re
from datetime import datetime
import requests

app = Flask(__name__)
VALID_API_KEY = os.getenv('API_KEY', 'test_key_123')
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
sessions = {}

def require_api_key(f):
    def wrapper(*args, **kwargs):
        if request.headers.get('X-API-Key') != VALID_API_KEY:
            return jsonify({'error': 'Invalid API key'}), 401
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'active_sessions': len(sessions), 'timestamp': datetime.utcnow().isoformat()}), 200

@app.route('/analyze', methods=['POST'])
@require_api_key
def analyze():
    data = request.get_json()
    if not data or 'sessionId' not in data or 'message' not in data or 'text' not in data['message']:
        return jsonify({'error': 'Missing required fields'}), 400
    
    session_id = data['sessionId']
    text = data['message']['text'].lower()
    
    if session_id not in sessions:
        sessions[session_id] = {'scamDetected': False, 'intel': {'upiIds': [], 'links': []}, 'count': 0}
    
    session = sessions[session_id]
    
    # Simple scam detection
    if not session['scamDetected']:
        if any(kw in text for kw in ['blocked', 'suspended', 'urgent', 'verify account', 'upi', 'transfer money']):
            session['scamDetected'] = True
    
    if not session['scamDetected']:
        return jsonify({'status': 'success', 'reply': None}), 200
    
    # Extract intelligence
    upi = re.findall(r'[\w.-]+@(?:paytm|okicici|okaxis|ybl|oksbi|upi)', text)
    links = re.findall(r'https?://[^\s]+', text)
    
    if upi:
        session['intel']['upiIds'].extend(upi)
    if links:
        session['intel']['links'].extend(links)
    
    session['count'] += 1
    
    # Send callback after extracting valuable intel
    if (upi or links) and session['count'] >= 2:
        try:
            requests.post(GUVI_CALLBACK_URL, json={
                "sessionId": session_id,
                "scamDetected": True,
                "totalMessagesExchanged": session['count'],
                "extractedIntelligence": {
                    "bankAccounts": [],
                    "upiIds": list(set(session['intel']['upiIds'])),
                    "phishingLinks": list(set(session['intel']['links'])),
                    "phoneNumbers": [],
                    "suspiciousKeywords": [kw for kw in ['urgent','verify','blocked'] if kw in text]
                },
                "agentNotes": "Scammer attempted financial fraud"
            }, timeout=3)
        except:
            pass
    
    # Human-like replies
    replies = [
        "Why is my account blocked? I haven't done anything wrong.",
        "Can you explain what happened to my account?",
        "I'm worried. How can I verify this is from the bank?",
        "Okay, what should I do to fix this?",
        "Is there a customer care number I can call?"
    ]
    
    return jsonify({'status': 'success', 'reply': replies[session['count'] % len(replies)]}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
