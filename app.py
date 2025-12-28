import os
import json
import time
import secrets
import spm
from flask import Flask, request, jsonify, send_from_directory, render_template

app = Flask(__name__, static_folder='static', template_folder='templates')

# In-memory storage for active sessions
# Token -> spm.Session
SESSIONS = {}

def get_session(token):
    sess = SESSIONS.get(token)
    if not sess:
        return None
    # Check timeout
    if time.time() - sess.last_activity > spm.SESSION_TIMEOUT:
        del SESSIONS[token]
        return None
    sess.last_activity = time.time()
    return sess

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
        
    if os.path.exists(spm.USER_FILE) and os.path.getsize(spm.USER_FILE) > 0:
         return jsonify({"error": "User already exists"}), 409
         
    if len(password) < 12:
        return jsonify({"error": "Password must be at least 12 characters"}), 400
        
    user = spm.initialUserData(username, password)
    spm.saveUserData(user)
    return jsonify({"success": True})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    try:
        user = spm.loadUserData()
    except FileNotFoundError:
        return jsonify({"error": "No user registered"}), 404
        
    if username != user.get("username"):
        return jsonify({"error": "Invalid credentials"}), 401
        
    salt = spm.base64decoding(user["salt"])
    params = user["argon2"]
    mk = spm.deriveMasterKey(password, salt, params)
    
    expectedAuth = spm.base64decoding(user["auth_tag"])
    if not spm.constantTimeCompare(expectedAuth, spm.compute_hmac(mk, b"auth verification v1")):
        return jsonify({"error": "Invalid credentials"}), 401
        
    # Check MAC
    mac_stored = spm.base64decoding(user.get("mac", ""))
    mac_key = spm.HKDFexpand(mk, info=b"file mac key", length=32, salt=salt)
    user_copy = dict(user)
    user_copy.pop("mac", None)
    if not spm.constantTimeCompare(mac_stored, spm.compute_hmac(mac_key, json.dumps(user_copy, sort_keys=True).encode("utf-8"))):
         return jsonify({"error": "Integrity check failed"}), 500

    # MFA Check
    if user.get("mfa", {}).get("enabled"):
        otp = data.get('otp')
        if not otp:
            return jsonify({"error": "MFA code required", "mfa_required": True}), 401
            
        if spm.pyotp is None:
             return jsonify({"error": "MFA enabled but server missing pyotp"}), 500
             
        k_auth = spm.HKDFexpand(mk, info=b"auth key", length=32, salt=salt)
        wrapped = spm.base64decoding(user["mfa"]["wrapped_seed"])
        wrapped_nonce = spm.base64decoding(user["mfa"]["wrapped_nonce"])
        try:
            seedBytes = spm.AESGCMdecrypt(k_auth, wrapped_nonce, wrapped)
            seedStr = seedBytes.decode("utf-8")
            totp = spm.pyotp.TOTP(seedStr)
            if not totp.verify(otp, valid_window=1):
                return jsonify({"error": "Invalid MFA code"}), 401
        except Exception:
             return jsonify({"error": "MFA processing error"}), 500

    # Decrypt Vault Key
    kv = spm.HKDFexpand(mk, info=b"vault key", length=32, salt=salt)
    
    # Create Session
    token = secrets.token_hex(32)
    sess = spm.Session(mk=mk, kv=kv, user=user, last_activity=time.time())
    SESSIONS[token] = sess
    
    return jsonify({"success": True, "token": token})

@app.route('/api/generate-deterministic', methods=['POST'])
def generate_deterministic():
    token = request.headers.get('Authorization')
    sess = get_session(token)
    if not sess:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    site = data.get('site')
    if not site:
        return jsonify({"error": "Site name required"}), 400
        
    passphrase = data.get('passphrase', '')
    try:
        length = int(data.get('length', spm.DEFEAULT_PASSWORD_LENGTH))
    except ValueError:
        length = spm.DEFEAULT_PASSWORD_LENGTH
        
    salt = spm.base64decoding(sess.user["salt"])
    tag = spm.siteHMACtag(sess.mk, site, passphrase, salt=salt)
    pwd = spm.passwordFromTag(tag, length=length, require_classes=True)
    
    return jsonify({"password": pwd})

@app.route('/api/check-session', methods=['GET'])
def check_session():
    token = request.headers.get('Authorization')
    if get_session(token):
        return jsonify({"valid": True})
    return jsonify({"valid": False}), 401

@app.route('/api/vault', methods=['GET'])
def get_vault():
    token = request.headers.get('Authorization')
    sess = get_session(token)
    if not sess:
        return jsonify({"error": "Unauthorized"}), 401
        
    try:
        vault = spm.vaultLoadEntries(sess)
        # Don't send passwords in list view for security, only when requested specifically? 
        # Actually standard PMs verify again or just show dots. 
        # For this API, we will just send it all but frontend can mask it.
        # Or even better, let's just send metadata and handle password retrieval separately if we want to be fancy.
        # But for simplicity, let's send it all.
        entries = vault.get("entries", [])
        return jsonify({"entries": entries})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/vault', methods=['POST'])
def add_entry():
    token = request.headers.get('Authorization')
    sess = get_session(token)
    if not sess:
        return jsonify({"error": "Unauthorized"}), 401
        
    data = request.json
    site = data.get('site')
    login = data.get('login')
    password = data.get('password')
    notes = data.get('notes', '')
    
    if not site or not login:
        return jsonify({"error": "Site and Login required"}), 400
        
    if not password:
        # Generate
        rnd = spm.base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")
        password = rnd[:20]
        
    vault = spm.vaultLoadEntries(sess)
    entry = {
        "id": spm.base64.urlsafe_b64encode(os.urandom(9)).decode("utf-8"),
        "site": site,
        "login": login,
        "password": password,
        "notes": notes,
        "created_at": int(time.time())
    }
    
    if "entries" not in vault:
        vault["entries"] = []
    vault["entries"].append(entry)
    
    spm.vaultSaveEntries(sess, vault)
    return jsonify({"success": True, "entry": entry})

@app.route('/api/logout', methods=['POST'])
def logout():
    token = request.headers.get('Authorization')
    if token in SESSIONS:
        del SESSIONS[token]
    return jsonify({"success": True})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
