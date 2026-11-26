"""
Generates a SYNTHETIC sample dataset (emails.csv) so the project runs offline.
For real accuracy, replace emails.csv with a public dataset (Kaggle: "Phishing Email
Dataset", Enron/SpamAssassin, etc.) that has two columns: text,label  (1=phishing, 0=safe).
"""
import csv
import random

random.seed(42)

brands = ["PayPal", "Amazon", "Netflix", "Microsoft", "Apple", "HDFC Bank", "SBI", "Google", "Instagram", "Paytm"]
bad_domains = ["secure-login-verify.com", "account-update-now.net", "paypa1-support.xyz", "bank-alert-kyc.info",
               "free-gift-claim.top", "verify-id-fast.ru", "login-microsoft-security.co"]
good_domains = ["github.com", "college.edu", "company.com", "docs.google.com", "linkedin.com", "wikipedia.org"]

phish_templates = [
    "Dear customer, your {b} account has been suspended. Verify your identity immediately at http://{d}/verify to avoid permanent closure.",
    "URGENT: unusual sign-in detected on your {b} account. Click http://{d}/secure now and confirm your password within 24 hours.",
    "Congratulations! You have won a free gift card from {b}. Claim your prize now: http://{d}/claim. Limited time offer!",
    "Your {b} KYC is expired. Update your details and bank card number at http://{d}/kyc or your account will be blocked.",
    "Action required: payment failed for your {b} subscription. Update billing information here http://{d}/billing immediately.",
    "Security alert from {b}: confirm your OTP and password at http://{d}/login. Failure to respond will lock your account.",
    "Dear user, you have a pending refund of Rs 4,999 from {b}. Submit your bank details at http://{d}/refund to receive it.",
    "Final notice! Your {b} password expires today. Click here http://{d}/reset to keep your account active.",
]
safe_templates = [
    "Hi team, the meeting is scheduled for tomorrow at 10 AM. Agenda and notes are in the shared doc: https://{g}/meeting-notes.",
    "Hello, please find attached the assignment for this week. Submit it before Friday through the college portal https://{g}.",
    "Thanks for your order. Your {b} receipt is attached. No action is needed. Contact support if you have questions.",
    "Hi, just a reminder that the project review is on Monday. Let me know if you want to reschedule. Regards, Priya.",
    "Your pull request was merged successfully. View the commit history at https://{g}/repo/commits.",
    "Hey, are we still meeting for lunch tomorrow? I will bring the notes from the lecture. See you there!",
    "Weekly newsletter: new articles on cloud computing and networking are available at https://{g}/blog.",
    "Dear student, your exam timetable has been published on the official website https://{g}. All the best.",
]

rows = []
for _ in range(300):
    rows.append((random.choice(phish_templates).format(b=random.choice(brands), d=random.choice(bad_domains)), 1))
for _ in range(300):
    rows.append((random.choice(safe_templates).format(b=random.choice(brands), g=random.choice(good_domains)), 0))
random.shuffle(rows)

with open("emails.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["text", "label"])
    w.writerows(rows)
print("emails.csv created with", len(rows), "rows")
