# Thiranex Cybersecurity Internship - Task Submissions

Four beginner-friendly cybersecurity mini projects, all written in **Python 3.9+**.

| # | Task | Folder | Due |
|---|------|--------|-----|
| 1 | Password Strength Analyzer | `task1_password_strength_analyzer/` | 02 Dec 2026 |
| 2 | Vulnerability Scanner (Mini Project) | `task2_vulnerability_scanner/` | 09 Dec 2026 |
| 3 | Phishing Email Detection Model | `task3_phishing_email_detection/` | 16 Dec 2026 |
| 4 | Secure Login System | `task4_secure_login_system/` | 23 Dec 2026 |

## Setup

```bash
git clone <your-repo-url>
cd thiranex-cybersecurity-internship
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

---

## Task 1 - Password Strength Analyzer

Evaluates a password and suggests stronger alternatives.

**Features**
- Checks length, character variety (upper/lower/digit/symbol) and uniqueness (common-password list, leetspeak variants, sequences like `1234`, repeats like `aaa`)
- Entropy estimate + score out of 100 with a label (Very Weak -> Very Strong)
- Suggests stronger passwords and a passphrase
- **Optional:** SQLite database stores only SHA-256 hashes of earlier passwords so a user cannot reuse them

```bash
cd task1_password_strength_analyzer
python password_analyzer.py                       # hidden prompt
python password_analyzer.py -p "password123"
python password_analyzer.py --user demo --save    # reuse prevention
```

**Learning outcome:** why length + randomness matter, what entropy means, and why passwords are stored as hashes, never as plain text.

---

## Task 2 - Vulnerability Scanner (Mini Project)

A simple educational scanner for hosts **you own or are authorised to test**.

**Features**
- TCP connect scan of common ports with banner grabbing
- Flags risky exposed services (Telnet, FTP, SMB, RDP, Redis, databases...)
- Detects outdated software from banners / `Server` header (`outdated_versions.json`)
- Web checks: missing security headers, version disclosure, HTTP without HTTPS redirect
- Generates `report.txt` and `report.json`

```bash
cd task2_vulnerability_scanner
python vuln_scanner.py --demo            # safe demo: starts a weak local server and scans it
python vuln_scanner.py                   # scans 127.0.0.1
python vuln_scanner.py -t 192.168.1.10   # asks for permission confirmation first
```

See `sample_report.txt` for example output.

> **Ethics:** only scan systems you have permission to test. This is a learning tool, not a replacement for Nmap / Nessus / OpenVAS.

---

## Task 3 - Phishing Email Detection Model

Scikit-learn model that classifies emails as **Phishing** or **Safe**.

**How it works**
- TF-IDF features from email text (words + bigrams)
- Hand-made features: number of URLs, IP-based URLs, `@` in URL, long URLs, suspicious TLDs, hyphens/digits in domain, non-HTTPS links, urgency / credential / prize keywords
- Trains Logistic Regression and Random Forest, keeps the better one
- Prints accuracy, precision/recall and a confusion matrix (`confusion_matrix.png`)

```bash
cd task3_phishing_email_detection
python generate_sample_dataset.py        # creates emails.csv (synthetic sample)
python phishing_model.py                 # train + evaluate
python phishing_model.py --predict "URGENT: verify your password at http://secure-login.xyz"
```

> **Note:** the bundled dataset is *synthetic*, so the ~100% accuracy is optimistic. For realistic results replace `emails.csv` with a public dataset (columns: `text`, `label` where 1 = phishing, 0 = safe), e.g. from Kaggle.

---

## Task 4 - Secure Login System

Flask web app with secure registration and login.

**Security features**
- Passwords hashed with **bcrypt** (automatic scrypt fallback if bcrypt is not installed)
- **SQL injection** protection with parameterised queries only
- Server-side **input validation** (username, email, password policy)
- **Session management**: HttpOnly + SameSite cookies, 20-minute timeout, session reset on login, proper logout
- **CSRF** tokens on every form
- **Brute-force protection**: 5 failed attempts -> 5-minute lock
- Security headers (CSP, X-Frame-Options, nosniff, Referrer-Policy)
- Generic login errors (no username enumeration)
- **Optional 2FA** with TOTP (Google Authenticator / Authy compatible)

```bash
cd task4_secure_login_system
python app.py                 # open http://127.0.0.1:5000
python test_app.py            # 9 automated security tests
```

For deployment set `SECRET_KEY` and `HTTPS=1` environment variables and run behind HTTPS.

---

## Project structure

```
thiranex-cybersecurity-internship/
├── README.md
├── requirements.txt
├── task1_password_strength_analyzer/
├── task2_vulnerability_scanner/
├── task3_phishing_email_detection/
└── task4_secure_login_system/
```

## Author

Name: _your name here_  |  Thiranex Cybersecurity Internship 2026
