"""
Task 1 - Password Strength Analyzer
-----------------------------------
Features
  * Checks length, complexity (upper/lower/digit/symbol) and uniqueness
    (common-password list, keyboard patterns, repeats, sequences)
  * Estimates entropy and gives a score (0-100) with a label
  * Suggests stronger alternatives
  * Optional: SQLite database that stores only SHA-256 hashes of old passwords
    so a user cannot reuse them (--user NAME --save)

Usage
  python password_analyzer.py                 # interactive (hidden input)
  python password_analyzer.py -p "MyPass123"  # one-off check
  python password_analyzer.py --user anu --save   # check + store hash for reuse prevention
"""
import argparse
import getpass
import hashlib
import math
import os
import re
import secrets
import sqlite3
import string

HERE = os.path.dirname(os.path.abspath(__file__))
COMMON_FILE = os.path.join(HERE, "common_passwords.txt")
DB_FILE = os.path.join(HERE, "password_history.db")

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]


# ---------- helpers ----------
def load_common():
    try:
        with open(COMMON_FILE, encoding="utf-8") as f:
            return {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        return set()


def has_sequence(pw, length=4):
    """Detect runs like abcd, 1234, qwer (forward or backward)."""
    low = pw.lower()
    seqs = [string.ascii_lowercase, string.digits] + KEYBOARD_ROWS
    for s in seqs:
        for variant in (s, s[::-1]):
            for i in range(len(variant) - length + 1):
                if variant[i:i + length] in low:
                    return True
    return False


def has_repeats(pw, n=3):
    return re.search(r"(.)\1{%d,}" % (n - 1), pw) is not None


def entropy_bits(pw):
    pool = 0
    if re.search(r"[a-z]", pw): pool += 26
    if re.search(r"[A-Z]", pw): pool += 26
    if re.search(r"\d", pw):    pool += 10
    if re.search(r"[^\w\s]", pw) or "_" in pw: pool += 32
    if " " in pw: pool += 1
    return len(pw) * math.log2(pool) if pool else 0.0


def sha256(pw):
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()


# ---------- core analysis ----------
def analyze(password, common=None):
    common = common if common is not None else load_common()
    issues, good = [], []
    score = 0

    # length
    n = len(password)
    if n < 8:
        issues.append("Too short (use at least 12 characters).")
    elif n < 12:
        score += 15
        issues.append("Okay length, but 12+ characters is much safer.")
    elif n < 16:
        score += 25; good.append("Good length (12+).")
    else:
        score += 30; good.append("Excellent length (16+).")

    # complexity
    checks = {
        "lowercase letters": re.search(r"[a-z]", password),
        "uppercase letters": re.search(r"[A-Z]", password),
        "digits": re.search(r"\d", password),
        "symbols": re.search(r"[^A-Za-z0-9]", password),
    }
    for name, ok in checks.items():
        if ok:
            score += 10; good.append(f"Contains {name}.")
        else:
            issues.append(f"Add {name}.")

    # uniqueness / patterns
    low = password.lower()
    stripped = re.sub(r"[^a-z]", "", low.translate(str.maketrans("4301!$5@7", "aeoilsast")))
    if low in common or stripped in common:
        score -= 40; issues.append("This is a very common password (found in breach lists).")
    else:
        score += 15; good.append("Not found in the common-password list.")
    if has_sequence(password):
        score -= 15; issues.append("Contains an easy sequence (abcd, 1234, qwer...).")
    if has_repeats(password):
        score -= 10; issues.append("Contains repeated characters (aaa, 111...).")
    if len(set(password)) < max(1, n) * 0.5 and n > 0:
        score -= 10; issues.append("Too many repeated characters overall.")

    bits = entropy_bits(password)
    if bits >= 70: score += 15
    elif bits >= 50: score += 8

    score = max(0, min(100, score))
    if score >= 80: label = "VERY STRONG"
    elif score >= 60: label = "STRONG"
    elif score >= 40: label = "MEDIUM"
    elif score >= 20: label = "WEAK"
    else: label = "VERY WEAK"

    return {"score": score, "label": label, "entropy_bits": round(bits, 1),
            "issues": issues, "good": good}


# ---------- suggestions ----------
def suggest(password, count=3):
    """Return stronger alternatives: hardened version of the input + random ones."""
    leet = str.maketrans({"a": "@", "e": "3", "i": "!", "o": "0", "s": "$"})
    symbols = "!@#$%^&*-_=+?"
    out = []
    base = re.sub(r"\s+", "", password) or "secure"
    for _ in range(count):
        word = base.translate(leet)
        word = "".join(c.upper() if secrets.randbelow(3) == 0 else c for c in word)
        tail = "".join(secrets.choice(string.digits + symbols) for _ in range(6))
        out.append(word + secrets.choice(symbols) + tail)
    # one passphrase style
    words = ["river", "tiger", "cloud", "rocket", "mango", "planet", "coffee",
             "thunder", "jungle", "silver", "pixel", "ocean", "falcon", "lemon"]
    phrase = "-".join(secrets.choice(words) for _ in range(4))
    out.append(f"{phrase.title()}-{secrets.randbelow(90) + 10}!")
    return out


# ---------- optional: password history DB ----------
def db_connect():
    con = sqlite3.connect(DB_FILE)
    con.execute("""CREATE TABLE IF NOT EXISTS history(
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     username TEXT NOT NULL,
                     pw_hash TEXT NOT NULL,
                     created TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    return con


def was_used_before(username, password):
    con = db_connect()
    row = con.execute("SELECT 1 FROM history WHERE username=? AND pw_hash=?",
                      (username, sha256(password))).fetchone()
    con.close()
    return row is not None


def save_password(username, password):
    con = db_connect()
    con.execute("INSERT INTO history(username, pw_hash) VALUES(?,?)",
                (username, sha256(password)))
    con.commit(); con.close()


# ---------- CLI ----------
def report(password, username=None, save=False):
    res = analyze(password)
    bar = "#" * (res["score"] // 5) + "-" * (20 - res["score"] // 5)
    print(f"\nStrength : {res['label']}  [{bar}] {res['score']}/100")
    print(f"Entropy  : ~{res['entropy_bits']} bits")
    for g in res["good"]:   print(f"  [+] {g}")
    for i in res["issues"]: print(f"  [-] {i}")

    if username:
        if was_used_before(username, password):
            print(f"\n[!] '{username}' has used this password before. Choose a new one.")
            return
        if save and res["score"] >= 40:
            save_password(username, password)
            print(f"\n[ok] Password hash saved for '{username}' (reuse will be blocked).")
        elif save:
            print("\n[!] Not saved: password is too weak.")

    if res["score"] < 80:
        print("\nStronger suggestions:")
        for s in suggest(password):
            print("   ", s)


def main():
    ap = argparse.ArgumentParser(description="Password Strength Analyzer")
    ap.add_argument("-p", "--password", help="password to check (avoid on shared shells)")
    ap.add_argument("--user", help="username for reuse-prevention database")
    ap.add_argument("--save", action="store_true", help="store hash of the password in the DB")
    args = ap.parse_args()
    pw = args.password or getpass.getpass("Enter password to analyze: ")
    report(pw, args.user, args.save)


if __name__ == "__main__":
    main()
