"""
Task 3 - Phishing Email Detection Model (Scikit-learn)
------------------------------------------------------
Pipeline
  1. Load dataset (emails.csv: text,label  -> 1 = phishing, 0 = safe)
  2. Extract features
       - TF-IDF of the email text (keywords such as "verify", "urgent", "password")
       - URL features: number of URLs, IP-address URLs, '@' in URL, long URLs,
         suspicious TLDs, hyphens/digits in domain, no-HTTPS links
       - Keyword counts: urgency / credential / money words
  3. Train Logistic Regression (and compare with Random Forest)
  4. Show accuracy, precision/recall, confusion matrix (also saved as PNG)
  5. Classify new emails:  python phishing_model.py --predict "your email text"

Run
  python generate_sample_dataset.py      # only if emails.csv is missing
  python phishing_model.py
"""
import argparse
import os
import re

import joblib
import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "emails.csv")
MODEL = os.path.join(HERE, "phishing_model.joblib")

URL_RE = re.compile(r"(https?://[^\s]+|www\.[^\s]+)", re.I)
SUSPICIOUS_TLDS = (".xyz", ".top", ".ru", ".info", ".tk", ".click", ".co", ".net")
URGENT = ["urgent", "immediately", "now", "final notice", "expires", "suspended", "within 24", "limited time", "blocked", "locked"]
CRED = ["password", "otp", "verify", "login", "confirm", "kyc", "bank", "card number", "identity", "billing"]
MONEY = ["won", "prize", "gift", "refund", "free", "congratulations", "claim"]


def url_features(text):
    urls = URL_RE.findall(text)
    f = {"n_urls": len(urls), "ip_url": 0, "at_in_url": 0, "long_url": 0,
         "bad_tld": 0, "hyphen_digit": 0, "no_https": 0}
    for u in urls:
        host = re.sub(r"^https?://", "", u, flags=re.I).split("/")[0]
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host): f["ip_url"] += 1
        if "@" in u: f["at_in_url"] += 1
        if len(u) > 60: f["long_url"] += 1
        if host.lower().endswith(SUSPICIOUS_TLDS): f["bad_tld"] += 1
        if "-" in host or re.search(r"\d", host): f["hyphen_digit"] += 1
        if u.lower().startswith("http://"): f["no_https"] += 1
    return f


def keyword_count(text, words):
    low = text.lower()
    return sum(low.count(w) for w in words)


def extract_features(texts):
    rows = []
    for t in texts:
        f = url_features(t)
        f["urgent_words"] = keyword_count(t, URGENT)
        f["cred_words"] = keyword_count(t, CRED)
        f["money_words"] = keyword_count(t, MONEY)
        f["exclaims"] = t.count("!")
        f["length"] = min(len(t), 2000) / 2000
        rows.append(f)
    return pd.DataFrame(rows)


class PhishingDetector:
    def __init__(self, model_type="logreg"):
        self.tfidf = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), min_df=2, max_features=5000)
        self.model_type = model_type
        self.clf = (LogisticRegression(max_iter=1000) if model_type == "logreg"
                    else RandomForestClassifier(n_estimators=200, random_state=42))

    def _matrix(self, texts, fit=False):
        text_part = self.tfidf.fit_transform(texts) if fit else self.tfidf.transform(texts)
        feat_part = csr_matrix(extract_features(texts).values.astype(float))
        return hstack([text_part, feat_part]).tocsr()

    def fit(self, texts, labels):
        self.clf.fit(self._matrix(texts, fit=True), labels)

    def predict(self, texts):
        return self.clf.predict(self._matrix(texts))

    def predict_proba(self, texts):
        return self.clf.predict_proba(self._matrix(texts))[:, 1]


def save_confusion_plot(cm, name):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return
    fig, ax = plt.subplots(figsize=(4, 4))
    ax.imshow(cm, cmap="Blues")
    ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
    ax.set_xticklabels(["Safe", "Phishing"]); ax.set_yticklabels(["Safe", "Phishing"])
    ax.set_xlabel("Predicted"); ax.set_ylabel("Actual"); ax.set_title(f"Confusion Matrix - {name}")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, cm[i, j], ha="center", va="center", color="black", fontsize=14)
    fig.tight_layout()
    fig.savefig(os.path.join(HERE, "confusion_matrix.png"), dpi=120)
    plt.close(fig)


def train():
    if not os.path.exists(DATA):
        raise SystemExit("emails.csv not found. Run: python generate_sample_dataset.py")
    df = pd.read_csv(DATA).dropna()
    X_train, X_test, y_train, y_test = train_test_split(
        df["text"].tolist(), df["label"].values, test_size=0.25, random_state=42, stratify=df["label"])

    best, best_acc, best_name = None, -1, ""
    for name in ("logreg", "random_forest"):
        det = PhishingDetector(name)
        det.fit(X_train, y_train)
        pred = det.predict(X_test)
        acc = accuracy_score(y_test, pred)
        cm = confusion_matrix(y_test, pred)
        print(f"\n=== {name} ===\nAccuracy: {acc:.4f}")
        print("Confusion matrix [rows=actual, cols=predicted] (Safe, Phishing):\n", cm)
        print(classification_report(y_test, pred, target_names=["Safe", "Phishing"], digits=3))
        if acc > best_acc:
            best, best_acc, best_name, best_cm = det, acc, name, cm

    joblib.dump(best, MODEL)
    save_confusion_plot(best_cm, best_name)
    print(f"Best model: {best_name} (accuracy {best_acc:.4f}) saved to phishing_model.joblib")
    print("NOTE: the bundled dataset is synthetic, so accuracy is optimistic. Use a real dataset for real-world results.")


def predict(text):
    if not os.path.exists(MODEL):
        train()
    det = joblib.load(MODEL)
    p = float(det.predict_proba([text])[0])
    label = "PHISHING" if p >= 0.5 else "SAFE"
    print(f"Result: {label}  (phishing probability {p:.2%})")
    feats = extract_features([text]).iloc[0]
    reasons = []
    if feats["n_urls"]: reasons.append(f"{int(feats['n_urls'])} URL(s) found")
    if feats["bad_tld"]: reasons.append("suspicious domain ending")
    if feats["no_https"]: reasons.append("link without HTTPS")
    if feats["urgent_words"]: reasons.append("urgency words")
    if feats["cred_words"]: reasons.append("asks for credentials / bank details")
    if feats["money_words"]: reasons.append("prize / money bait")
    if reasons:
        print("Signals:", ", ".join(reasons))


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Phishing email detector")
    ap.add_argument("--predict", help="email text to classify")
    a = ap.parse_args()
    predict(a.predict) if a.predict else train()
