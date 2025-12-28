import requests
import sys

BASE = "http://localhost:5000/api"

def test():
    # 1. Register
    print("Registering...")
    res = requests.post(f"{BASE}/register", json={"username": "api_test", "password": "password123456"})
    if res.status_code == 409:
        print("User exists, proceeding to login.")
    elif res.status_code != 200:
        print(f"Register failed: {res.text}")
        return
    else:
        print("Registered.")

    # 2. Login
    print("Logging in...")
    res = requests.post(f"{BASE}/login", json={"username": "api_test", "password": "password123456"})
    if res.status_code != 200:
        print(f"Login failed: {res.text}")
        return
    token = res.json().get("token")
    print(f"Logged in. Token: {token[:10]}...")

    # 3. Add Entry
    print("Adding entry...")
    headers = {"Authorization": token}
    res = requests.post(f"{BASE}/vault", headers=headers, json={"site": "test.com", "login": "tester", "password": "securepassword", "notes": "test notes"})
    if res.status_code != 200:
        print(f"Add entry failed: {res.text}")
        return
    print("Entry added.")

    # 4. Get Vault
    print("Getting vault...")
    res = requests.get(f"{BASE}/vault", headers=headers)
    if res.status_code != 200:
        print(f"Get vault failed: {res.text}")
        return
    entries = res.json().get("entries", [])
    print(f"Vault entries: {len(entries)}")
    for e in entries:
        if e["site"] == "test.com":
            print("Found test entry!")
            return

    print("Test entry NOT found.")

if __name__ == "__main__":
    test()
