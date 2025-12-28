import requests
import pyotp
import time
import sys

BASE = "http://localhost:5000/api"
s = requests.Session()

def test():
    # 1. Register
    username = f"test_mfa_{int(time.time())}"
    password = "password123456"
    print(f"Registering {username}...")
    res = s.post(f"{BASE}/register", json={"username": username, "password": password})
    if res.status_code != 200:
        # Use existing user?
        print(f"Register failed (maybe exists): {res.text}")
        # Try login
    
    # 2. Login
    print("Logging in...")
    res = s.post(f"{BASE}/login", json={"username": username, "password": password})
    if res.status_code != 200:
        print(f"Login failed: {res.text}")
        sys.exit(1)
        
    token = res.json()["token"]
    headers = {"Authorization": token}
    print(f"Logged in. Token: {token[:10]}...")
    
    # 3. Check Status
    print("Checking status...")
    res = s.get(f"{BASE}/mfa/status", headers=headers)
    print(f"Status: {res.json()}")
    assert res.json()["enabled"] == False
    
    # 4. Setup
    print("Setting up MFA...")
    res = s.post(f"{BASE}/mfa/setup", headers=headers)
    print(f"Setup Res: {res.json()}")
    assert res.status_code == 200
    seed = res.json()["seed"]
    assert seed is not None
    
    # 5. Enable
    print(f"Enabling MFA with seed {seed}...")
    totp = pyotp.TOTP(seed)
    # Generate OTP
    otp = totp.now()
    # It might fail if time sync is off, try +/- windows inside server if needed, but server uses valid_window=1 (30s*1 = 30s tolerance)
    # Client generates now.
    res = s.post(f"{BASE}/mfa/enable", json={"otp": otp}, headers=headers)
    print(f"Enable Res: {res.json()}")
    
    if res.status_code != 200:
        print("Enable failed, retrying with previous/next interval?")
        # Wait a bit?
        time.sleep(1)
        otp = totp.now()
        res = s.post(f"{BASE}/mfa/enable", json={"otp": otp}, headers=headers)
        print(f"Enable Retry Res: {res.json()}")
    assert res.status_code == 200
    
    # 6. Check Status
    print("Checking status again...")
    res = s.get(f"{BASE}/mfa/status", headers=headers)
    print(f"Status: {res.json()}")
    assert res.json()["enabled"] == True
    
    # 7. Relogin test
    print("Logout...")
    s.post(f"{BASE}/logout", headers=headers)
    
    print("Relogin without OTP...")
    res = s.post(f"{BASE}/login", json={"username": username, "password": password})
    print(f"Login Res: {res.status_code} {res.json()}")
    assert res.status_code == 401
    assert res.json().get("mfa_required") == True
    
    print("Relogin with OTP...")
    otp = totp.now()
    res = s.post(f"{BASE}/login", json={"username": username, "password": password, "otp": otp})
    print(f"Login Res: {res.status_code} {res.json()}")
    assert res.status_code == 200
    token = res.json()["token"]
    headers = {"Authorization": token}
    
    # 8. Disable
    print("Disabling MFA...")
    res = s.post(f"{BASE}/mfa/disable", headers=headers)
    print(f"Disable Res: {res.json()}")
    assert res.status_code == 200
    
    print("Checking status final...")
    res = s.get(f"{BASE}/mfa/status", headers=headers)
    assert res.json()["enabled"] == False
    
    print("SUCCESS: MFA FLOW VERIFIED")

if __name__ == "__main__":
    try:
        test()
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)
