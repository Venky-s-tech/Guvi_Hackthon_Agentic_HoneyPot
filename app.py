from flask import Flask, request, jsonify
import os
import re
from datetime import datetime
import requests

app = Flask(__name__)
VALID_API_KEY = "test123456"  # Hardcoded for hackathon
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"  # NO SPACES!
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
    return jsonify({
        'status': 'healthy',
        'active_sessions': len(sessions),
        'timestamp': datetime.utcnow().isoformat()
    }), 200

@app.route('/analyze', methods=['POST'])
@require_api_key
def analyze():
    data = request.get_json()
    if not data or 'sessionId' not in data or 'message' not in 
        return jsonify({'error': 'Missing required fields'}), 400
    
    if 'text' not in data['message']:
        return jsonify({'error': 'Missing message text'}), 400
    
    session_id = data['sessionId']
    text = data['message']['text']
    
    if session_id not in sessions:
        sessions[session_id] = {
            'scamDetected': False,
            'intelligence': {'upiIds': [], 'phishingLinks': [], 'bankAccounts': []},
            'messageCount': 0
        }
    
    session = sessions[session_id]
    
    if not session['scamDetected']:
        scam_keywords = ['blocked', 'suspended', 'urgent', 'verify account', 'upi id', 'transfer money', 'processing fee']
        if any(kw in text.lower() for kw in scam_keywords):
            session['scamDetected'] = True
    
    if not session['scamDetected']:
        return jsonify({'status': 'success', 'reply': None}), 200
    
    upi_matches = re.findall(r'[\w.-]+@(?:paytm|okicici|okaxis|ybl|oksbi|upi|axis|icici|sbi)', text, re.IGNORECASE)
    link_matches = re.findall(r'https?://[^\s]+', text)
    bank_matches = re.findall(r'\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}', text)
    
    if upi_matches:
        session['intelligence']['upiIds'].extend(upi_matches)
    if link_matches:
        session['intelligence']['phishingLinks'].extend(link_matches)
    if bank_matches:
        session['intelligence']['bankAccounts'].extend(bank_matches)
    
    session['messageCount'] += 1
    
    valuable_intel = session['intelligence']['upiIds'] or session['intelligence']['phishingLinks'] or session['intelligence']['bankAccounts']
    should_callback = (valuable_intel and session['messageCount'] >= 2) or session['messageCount'] >= 5
    
    if should_callback:
        try:
            callback_data = {
                "sessionId": session_id,
                "scamDetected": True,
                "totalMessagesExchanged": session['messageCount'],
                "extractedIntelligence": {
                    "bankAccounts": list(set(session['intelligence']['bankAccounts'])),
                    "upiIds": list(set(session['intelligence']['upiIds'])),
                    "phishingLinks": list(set(session['intelligence']['phishingLinks'])),
                    "phoneNumbers": [],
                    "suspiciousKeywords": [kw for kw in ['urgent','verify','blocked','suspended','transfer','fee'] if kw in text.lower()]
                },
                "agentNotes": "Scammer used urgency tactics to extract financial details"
            }
            requests.post(GUVI_CALLBACK_URL, json=callback_data, timeout=3)
        except:
            pass
    
    replies = [
        "Why is my account being blocked? I haven't done anything wrong.",
        "Can you please explain what happened to my account?",
        "I'm worried about this. How can I verify this is really from the bank?",
        "Okay, what should I do to fix this issue?",
        "I don't understand. Can you give me more details?",
        "Is there a customer care number I can call to confirm?",
        "I'm confused. Can you explain step by step what I need to do?"
    ]
    
    reply = replies[session['messageCount'] % len(replies)]
    return jsonify({'status': 'success', 'reply': reply}), 200

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
