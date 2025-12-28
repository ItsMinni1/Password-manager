#!/usr/bin/env python3
import os
import sys
import json
import time
import base64
import hmac
import hashlib
import getpass
import tempfile
import pyotp
import pyperclip
import secrets
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

USER_FILE = "userData.json"
LOCK_FILE = USER_FILE + ".lock"
SESSION_TIMEOUT = 120
DEFEAULT_PASSWORD_LENGTH = 16
DEFAULT_ARGON2_PARAMS = {
    "time-cost": 1,
    "memory-cost": 2000 * 1024, 
    "parallelism": 8,
    "hash_len": 128
}

ALLOWED_SYMBOLS = "!@#$%&*()-_[]{}<>?/"

def base64encoding(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def base64decoding(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

def atomicWriteJson(path: str, obj: Any) -> None:
    dirpath = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmpname = tempfile.mkstemp(dir=dirpath)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tmp:
            json.dump(obj, tmp, indent=4, sort_keys=True)
            tmp.flush()
            os.fsync(tmp.fileno())
        os.replace(tmpname, path)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
    finally:
        if os.path.exists(tmpname):
            try:
                os.remove(tmpname)
            except Exception:
                pass

def try_acquire_lock(timeout: int = 5) -> bool:
    start = time.time()
    while True:
        try:
            fd = os.open(LOCK_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            with os.fdopen(fd, "w") as f:
                f.write(str(os.getpid()))
            return True
        except FileExistsError:
            if (time.time() - start) > timeout:
                return False
            time.sleep(0.05)

def release_lock() -> None:
    try:
        if os.path.exists(LOCK_FILE):
            os.remove(LOCK_FILE)
    except Exception:
        pass

def constantTimeCompare(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)

def deriveMasterKey(password: str, salt: bytes, params: Dict[str, int]) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=params["time-cost"],
        memory_cost=params["memory-cost"],
        parallelism=params["parallelism"],
        hash_len=params["hash_len"],
        type=Type.ID,
    )

def compute_hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

def HKDFexpand(mk: bytes, info: bytes = b"", length: int = 32, salt: Optional[bytes] = None) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info
    )
    return hkdf.derive(mk)

def AESGCMencrypt(key: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ct

def AESGCMdecrypt(key: bytes, nonce: bytes, ct: bytes, aad: Optional[bytes] = None) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, aad)

def canonicalizeSite(site: str) -> bytes:
    return site.strip().lower().encode("utf-8")

def siteHMACtag(mk: bytes, site: str, passphrase: str = "", salt: Optional[bytes] = None) -> bytes:
    site_b = canonicalizeSite(site)
    inner = hashlib.sha256(site_b + b"\x00" + passphrase.encode("utf-8")).digest()
    site_key = HKDFexpand(mk, info=b"site key", length=32, salt=salt)
    return hmac.new(site_key, inner, hashlib.sha256).digest()

allowedSymbols = ALLOWED_SYMBOLS

def passwordFromTag(tag: bytes, length: int = DEFEAULT_PASSWORD_LENGTH, require_classes: bool = True) -> str:
    lowers = "abcdefghijklmnopqrstuvwxyz"
    uppers = lowers.upper()
    digits = "0123456789"
    symbols = allowedSymbols
    alphabet = lowers + uppers + digits + symbols

    def bytesToPassword(b: bytes, ln: int) -> str:
        out = []
        idx = 0
        acc = 0
        acc_bits = 0
        for _ in range(ln):
            while acc_bits < 16:
                if idx >= len(b):
                    b = hashlib.sha256(b).digest()
                    idx = 0
                acc = (acc << 8) | b[idx]
                idx += 1
                acc_bits += 8
            acc_bits -= 11
            val = (acc >> acc_bits) & 0x7FF
            out.append(alphabet[val % len(alphabet)])
        return "".join(out)

    counter = 0
    cur_tag = tag
    while True:
        pwd = bytesToPassword(cur_tag, length)
        if not require_classes:
            return pwd
        hasLower = any(c in lowers for c in pwd)
        hasUpper = any(c in uppers for c in pwd)
        hasDigit = any(c in digits for c in pwd)
        hasSymbol = any(c in symbols for c in pwd)
        if hasLower and hasUpper and hasDigit and hasSymbol:
            return pwd
        counter += 1
        cur_tag = hashlib.sha256(cur_tag + counter.to_bytes(4, "big")).digest()

def initialUserData(username: str, password: str, argon2_params: Dict[str, int] = DEFAULT_ARGON2_PARAMS) -> Dict[str, Any]:
    salt = os.urandom(16)
    mk = deriveMasterKey(password, salt, argon2_params)
    authTag = compute_hmac(mk, b"auth verification v1")
    kv = HKDFexpand(mk, info=b"vault key", length=32, salt=salt)
    vault_plain = json.dumps({"entries": []}).encode("utf-8")
    nonce, ct = AESGCMencrypt(kv, vault_plain)
    user = {
        "version": 1,
        "username": username,
        "argon2": argon2_params,
        "salt": base64encoding(salt),
        "auth_tag": base64encoding(authTag),
        "mfa": {"enabled": False, "wrapped_seed": None, "wrapped_nonce": None},
        "vault": {"nonce": base64encoding(nonce), "ct": base64encoding(ct)},
        "created_at": int(time.time())
    }
    mac_key = HKDFexpand(mk, info=b"file mac key", length=32, salt=salt)
    user_copy = dict(user)
    mac = compute_hmac(mac_key, json.dumps(user_copy, sort_keys=True).encode("utf-8"))
    user["mac"] = base64encoding(mac)
    return user

def loadUserData() -> Dict[str, Any]:
    if not os.path.exists(USER_FILE):
        raise FileNotFoundError("No user data found. Register first.")
    with open(USER_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def saveUserData(user: Dict[str, Any]) -> None:
    if not try_acquire_lock():
        raise RuntimeError("Unable to acquire file lock for writing.")
    try:
        atomicWriteJson(USER_FILE, user)
    finally:
        release_lock()

@dataclass
class Session:
    mk: bytes
    kv: bytes
    user: Dict[str, Any]
    last_activity: float

def registerUserInteractive() -> None:
    if os.path.exists(USER_FILE) and os.path.getsize(USER_FILE) > 0:
        print("User already exists! Use login.")
        return
    username = input("Choose a username: ").strip()
    while True:
        password = getpass.getpass("Choose a strong master password: ")
        password2 = getpass.getpass("Confirm master password: ")
        if password != password2:
            print("Passwords do not match, try again :( ")
        elif len(password) < 12:
            print("Please use at least 12 characters >:( ")
        else:
            break
    user = initialUserData(username, password)
    saveUserData(user)
    print("User registered and vault initialized! :D ")

def loginInteractive() -> Optional[Session]:
    try:
        user = loadUserData()
    except FileNotFoundError:
        print("No user registered :( Please register first.")
        return None
    username = input("Username: ").strip()
    if username != user.get("username"):
        print("Unkown username :/ ")
        return None
    password = getpass.getpass("Master password: ")
    salt = base64decoding(user["salt"])
    params = user["argon2"]
    mk = deriveMasterKey(password, salt, params)
    expectedAuth = base64decoding(user["auth_tag"])
    if not constantTimeCompare(expectedAuth, compute_hmac(mk, b"auth verification v1")):
        print("Invalid master password >:( ")
        return None
    mac_stored = base64decoding(user.get("mac", ""))
    mac_key = HKDFexpand(mk, info=b"file mac key", length=32, salt=salt)
    user_copy = dict(user)
    user_copy.pop("mac", None)
    if not constantTimeCompare(mac_stored, compute_hmac(mac_key, json.dumps(user_copy, sort_keys=True).encode("utf-8"))):
        print("File integrity check failed. Possible tampering.")
        return None
    if user.get("mfa", {}).get("enabled"):
        if pyotp is None:
            print("MFA enabled but pyotp is not installed :/ Do that first ")
            return None
        k_auth = HKDFexpand(mk, info=b"auth key", length=32, salt=salt)
        wrapped = base64decoding(user["mfa"]["wrapped_seed"])
        wrapped_nonce = base64decoding(user["mfa"]["wrapped_nonce"])
        try:
            seedBytes = AESGCMdecrypt(k_auth, wrapped_nonce, wrapped)
        except Exception:
            print("Failed to decrypt MFA seed")
            return None
        seedStr = seedBytes.decode("utf-8")
        totp = pyotp.TOTP(seedStr)
        code = input("Enter TOTP code: ").strip()
        if not totp.verify(code, valid_window=1):
            print("Invalid TOTP code.")
            return None
        print("MFA verified!")
    kv = HKDFexpand(mk, info=b"vault key", length=32, salt=salt)
    try:
        nonce = base64decoding(user["vault"]["nonce"])
        ct = base64decoding(user["vault"]["ct"])
        plaintext = AESGCMdecrypt(kv, nonce, ct)
        _ = json.loads(plaintext.decode("utf-8"))
    except Exception:
        print("Failed to decrypt vault :( ")
        return None
    sess = Session(mk=mk, kv=kv, user=user, last_activity=time.time())
    print("Login successful! Session unlocked :D ")
    return sess

def vaultLoadEntries(sess: Session) -> Dict[str, Any]:
    user = sess.user
    nonce = base64decoding(user["vault"]["nonce"])
    ct = base64decoding(user["vault"]["ct"])
    pt = AESGCMdecrypt(sess.kv, nonce, ct)
    return json.loads(pt.decode("utf-8"))

def vaultSaveEntries(sess: Session, vaultObj: Dict[str, Any]) -> None:
    nonce, ct = AESGCMencrypt(sess.kv, json.dumps(vaultObj).encode("utf-8"))
    sess.user["vault"]["nonce"] = base64encoding(nonce)
    sess.user["vault"]["ct"] = base64encoding(ct)
    sess.user["last_modified"] = int(time.time())
    mac_key = HKDFexpand(sess.mk, info=b"file mac key", length=32, salt=base64decoding(sess.user["salt"]))
    user_copy = dict(sess.user)
    user_copy.pop("mac", None)
    mac = compute_hmac(mac_key, json.dumps(user_copy, sort_keys=True).encode("utf-8"))
    sess.user["mac"] = base64encoding(mac)
    saveUserData(sess.user)

def vaultAddEntry(sess: Session) -> None:
    sess.last_activity = time.time()
    site = input("Site i.e., example.com ").strip()
    login = input("Login/username: ").strip()
    useGenerated = input("Generate a strong master password (Y/N): ").strip().lower() == "y"
    if useGenerated:
        rnd = base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")
        pwd = rnd[:20]
        print("Generated password will be stored in the vault.")
    else:
        pwd = getpass.getpass("Password for this site: ")
    notes = input("Notes (optional): ").strip()
    vault = vaultLoadEntries(sess)
    entry = {
        "id": base64.urlsafe_b64encode(os.urandom(9)).decode("utf-8"),
        "site": site,
        "login": login,
        "password": pwd,
        "notes": notes,
        "created_at": int(time.time())
    }
    vault["entries"].append(entry)
    vaultSaveEntries(sess, vault)
    print("Entry saved to vault! :D ")

def vaultListSites(sess: Session) -> None:
    sess.last_activity = time.time()
    vault = vaultLoadEntries(sess)
    entries = vault.get("entries", [])
    if not entries:
        print("Vault empty :( ")
        return
    print("Saved sites: ")
    for e in entries:
        print(f" - {e['site']}(id: {e['id']})")
    print("")

def vaultGetEntry(sess: Session) -> None:
    sess.last_activity = time.time()
    site = input("Enter site name to look up: ").strip()
    vault = vaultLoadEntries(sess)
    for e in vault.get("entries", []):
        if e["site"].strip().lower() == site.strip().lower():
            print(f"\nSite: {e['site']}")
            print(f"Login: {e['login']}")
            print(f"Password: {e['password']}")
            if pyperclip is not None:
                try:
                    pyperclip.copy(e["password"])
                    print("Password copied to clipboard!")
                except Exception:
                    pass
            print("")
            return
    print("Entry not found :( ")

def enableMFA(sess: Session) -> None:
    if pyotp is None:
        print(" pyotp not available. Install to use Multi-factor Authentication")
        return
    sess.last_activity = time.time()
    user = sess.user
    if user.get("mfa", {}).get("enabled"):
        print("MFA enabled.")
        return
    seed = pyotp.random_base32()
    uri = pyotp.totp.TOTP(seed).provisioning_uri(name=user["username"], issuer_name="SecurePasswordManager")
    print("Save this seed in your authenticator app")
    print("TOTP seed (base32): ", seed)
    k_auth = HKDFexpand(sess.mk, info=b"auth key", length=32, salt=base64decoding(user["salt"]))
    nonce, wrapped = AESGCMencrypt(k_auth, seed.encode("utf-8"))
    user["mfa"]["wrapped_seed"] = base64encoding(wrapped)
    user["mfa"]["wrapped_nonce"] = base64encoding(nonce)
    user["mfa"]["enabled"] = True
    mac_key = HKDFexpand(sess.mk, info=b"file mac key", length=32, salt=base64decoding(user["salt"]))
    user_copy = dict(user)
    user_copy.pop("mac", None)
    user["mac"] = base64encoding(compute_hmac(mac_key, json.dumps(user_copy, sort_keys=True).encode("utf-8")))
    saveUserData(user)
    print("MFA enabled. Log in with to check.")

def disableMFA(sess: Session) -> None:
    sess.last_activity = time.time()
    user = sess.user
    if not user.get("mfa", {}).get("enabled"):
        print("MFA not enabled girl")
        return
    confirm = input("Disabling MFA. Press y to continue: ")
    if confirm.strip() != 'y':
        print("Disabling MDA - Process aborted.")
        return
    user["mfa"] = {"enabled": False, "wrapped_seed": None, "wrapped_nonce": None}
    mac_key = HKDFexpand(sess.mk, info=b"file mac key", length=32, salt=base64decoding(user["salt"]))
    user_copy = dict(user)
    user_copy.pop("mac", None)
    user["mac"] = base64encoding(compute_hmac(mac_key, json.dumps(user_copy, sort_keys=True).encode("utf-8")))
    saveUserData(user)
    print("MFA disabled successfully")

def changeMasterPassword(sess: Session) -> Optional[Session]:
    sess.last_activity = time.time()
    user = sess.user
    vault = vaultLoadEntries(sess)
    while True:
        newPass = getpass.getpass("New master password: ")
        newPass2 = getpass.getpass("Confirm password: ")
        if newPass != newPass2:
            print("Passwords do not match")
            continue
        if len(newPass) < 12:
            print("Use atleast 12 characters >:( ")
            continue
        break
    newSalt = os.urandom(16)
    newParams = user["argon2"]
    newMk = deriveMasterKey(newPass, newSalt, newParams)
    newAuth = compute_hmac(newMk, b"auth verification v1")
    newKV = HKDFexpand(newMk, info=b"vault key", length=32, salt=newSalt)
    if user.get("mfa", {}).get("enabled"):
        k_auth_old = HKDFexpand(sess.mk, info=b"auth key", length=32, salt=base64decoding(user["salt"]))
        wrapped = base64decoding(user["mfa"]["wrapped_seed"])
        wrapped_nonce = base64decoding(user["mfa"]["wrapped_nonce"])
        seed_bytes = AESGCMdecrypt(k_auth_old, wrapped_nonce, wrapped)
        k_auth_new = HKDFexpand(newMk, info=b"auth key", length=32, salt=newSalt)
        newNonce, newWrapped = AESGCMencrypt(k_auth_new, seed_bytes)
        user["mfa"]["wrapped_seed"] = base64encoding(newWrapped)
        user["mfa"]["wrapped_nonce"] = base64encoding(newNonce)
    newNonce, newCt = AESGCMencrypt(newKV, json.dumps(vault).encode("utf-8"))
    user["salt"] = base64encoding(newSalt)
    user["auth_tag"] = base64encoding(newAuth)
    user["vault"]["nonce"] = base64encoding(newNonce)
    user["vault"]["ct"] = base64encoding(newCt)
    mac_key = HKDFexpand(newMk, info=b"file mac key", length=32, salt=newSalt)
    user_copy = dict(user)
    user_copy.pop("mac", None)
    user["mac"] = base64encoding(compute_hmac(mac_key, json.dumps(user_copy, sort_keys=True).encode("utf-8")))
    saveUserData(user)
    print("Master password changed & Vault re-encrypted sucessfully!")
    return Session(mk=newMk, kv=newKV, user=user, last_activity=time.time())

def deterministicModeInteractive(sess: Optional[Session]) -> None:
    if sess is not None:
        mk = sess.mk
        salt = base64decoding(sess.user["salt"])
    else:
        try:
            user = loadUserData()
        except FileNotFoundError:
            print("No user registered >:( ")
            return
        username = input("Username: ").strip()
        if username != user["username"]:
            print("Unkown username")
            return
        pwd = getpass.getpass("Master password: ")
        salt = base64decoding(user["salt"])
        mk = deriveMasterKey(pwd, salt, user["argon2"])
        if not constantTimeCompare(base64decoding(user["auth_tag"]), compute_hmac(mk, b"auth verification v1")):
            print("Inavlid master password (who you lil bro?)")
            return
    site = input("Site name i.e, example.com : ").strip()
    if not site:
        print("Site cannot be empty")
        return
    passphrase = input("Optional passphrase, leave blank if none: ").strip()
    try:
        length = int(input(f"Requested length, default is {DEFEAULT_PASSWORD_LENGTH}: ") or DEFEAULT_PASSWORD_LENGTH)
    except ValueError:
        length = DEFEAULT_PASSWORD_LENGTH
    tag = siteHMACtag(mk, site, passphrase, salt=salt)
    pwd = passwordFromTag(tag, length=length, require_classes=True)
    print(f"\nDeterministic password for {site}: {pwd}")
    pyperclip.copy(pwd)
    print("Password copied to clipboard!")
    print("")

def mainMenu():
    print("Welcome to your personal password manager! ")
    print("1. Register")
    print("2. Login")
    print("3. Quit")
    choice = input("Enter your choice to continue: ").strip()
    return choice

def sessionMenu():
    print("Sesshion menu")
    print("1. Mode A - Deterministic Password Generator")
    print("2. Mode B - Secure Vault : Add password")
    print("3. Mode B - Secure Vault : Get password")
    print("4. Mode B - Secure Vault : View saved sites")
    print("5. Enable TOTP Multifactor Authentication")
    print("6. Disable TOTP Multifactor Authentication")
    print("7. Change yo master password: ")
    print("8. Logout :( ")
    return input("Choice: ").strip()

def runCLI():
    while True:
        c = mainMenu()
        if c == "1":
            registerUserInteractive()
        elif c == "2":
            sess = loginInteractive()
            if not sess:
                continue
            while True:
                choice = sessionMenu()
                if time.time() - sess.last_activity > SESSION_TIMEOUT:
                    print("Session timed out. Login again >:) ")
                    break
                if choice == "1":
                    deterministicModeInteractive(sess)
                elif choice == "2":
                    vaultAddEntry(sess)
                elif choice == "3":
                    vaultGetEntry(sess)
                elif choice == "4":
                    vaultListSites(sess)
                elif choice == "5":
                    enableMFA(sess)
                elif choice == "6":
                    disableMFA(sess)
                elif choice == "7":
                    new_sess = changeMasterPassword(sess)
                    if new_sess:
                        sess = new_sess
                elif choice == "8":
                    print("Logging out...")
                    break
                else:
                    print("Unknown choice (?)")
        elif c == "3":
            print("Bubye :( ")
            break
        else:
            print("Invalid option :( ")

if __name__ == "__main__":
    runCLI()