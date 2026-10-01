#!/usr/bin/env python3
"""Port of PhishingScanService.evaluateTextHeuristicFallback for tuning.
Measures against SMS Spam Collection + curated 20."""
import re, csv
from url_v4 import v4 as url_v4, features as url_features
import json
P = json.load(open("/home/hatch/workspace/gillnet-project/url_v4_params.json"))
UW, UTHR = P["W"], P["thr"]

TARGET_BRANDS = ["Contoso", "Workplace Alert", "HR Team", "Human Resources",
                 "PayPal", "Microsoft", "Netflix", "Apple", "Google",
                 "Chase", "Bank of America", "Wells Fargo", "Amazon",
                 "DHL", "FedEx", "USPS", "Binance", "Coinbase", "MetaMask"]
URGENCY_TRIGGERS = [
    "device and internet usage policy", "viewing of inappropriate material",
    "inappropriate material online", "prohibited online activity",
    "recorded your webcam", "recorded your screen", "compromised browsing history",
    "facing termination", "disciplinary interview", "aforementioned evidence",
    "sign-in attempt was blocked", "someone just used your password",
    "from a non-google app", "review your account activity",
    "immediately", "urgent", "action required", "within 24 hours",
    "account suspended", "blocked", "restricted", "expire today",
    "unauthorized access", "act now", "final notice", "deactivated",
    "locked out", "unusual activity", "critical alert", "security alert"]
HARVESTING_TRIGGERS = [
    "view recorded evidence", "review recorded evidence", "download evidence",
    "view evidence", "check activity", "checkactivity", "review account activity",
    "sign in to your account", "verify your account", "enter password",
    "verify password", "update password", "confirm your pin",
    "provide otp", "security question", "social security", "card number",
    "cvv", "expiry date", "seed phrase", "secret key", "billing information",
    "login credentials", "reset password", "click here to unlock",
    "access document", "open attachment"]

URL_RE = re.compile(r"\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.](?:com|org|net|xyz|top|ru|co|info|biz|site|live|online|security|app|vip|club)/?)[^\s<>'\"\)\]]+)", re.I)
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})")


def analyze_text(text, urgency=URGENCY_TRIGGERS, harvesting=HARVESTING_TRIGGERS,
                 brands=TARGET_BRANDS):
    lower = text.lower()
    risk = 10
    detected_brand = None
    sender_spoofed = False
    credential_harvesting = False
    urgency_hits = []

    # timetable whitelist (same as Java)
    is_tt = (any(w in lower for w in ("timetable", "time table", "schedule", "routine", "syllabus", "lecture", "semester"))
             and any(w in lower for w in ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "room", "am", "pm")))
    if is_tt:
        return ("SAFE", 0)

    norm = re.sub(r"(?i)hxxp", "http", text).replace("[.]", ".")
    urls = []
    for m in URL_RE.finditer(norm):
        u = re.sub(r"[.,;]+$", "", m.group(0))
        if u not in urls:
            urls.append(u)
    malicious = 0
    for u in urls:
        if not u.startswith(("http://", "https://")):
            u = "http://" + u
        pred, score = url_v4(u, UW, UTHR)
        if pred == "PHISHING" or score >= 60:
            malicious += 1
            risk = max(risk + 40, 90)

    for brand in brands:
        if brand.lower() in lower:
            detected_brand = brand
            risk += 20
            break
    if "[.]" in text or "[@]" in text:
        risk += 15
    em = EMAIL_RE.search(text.replace("[.]", ".").replace("[@]", "@"))
    if em:
        dom = em.group(1).lower()
        if detected_brand:
            bl = detected_brand.lower()
            if bl not in dom or "webnotifications" in dom or "mail-delivery" in dom:
                sender_spoofed = True
                risk += 45
        elif any(w in text for w in ("workplace", "hr", "policy", "contoso")):
            if any(w in dom for w in ("webnotifications", "mail-delivery", "notification")):
                sender_spoofed = True
                risk += 45
    for t in urgency:
        if t in lower:
            urgency_hits.append(t)
            risk += 15
    for t in harvesting:
        if t in lower:
            credential_harvesting = True
            risk += 25
            break
    risk = min(100, max(5, risk))
    if malicious > 0:
        return ("PHISHING", max(risk, 90))
    if risk >= 70 or sender_spoofed or (credential_harvesting and urgency_hits):
        return ("PHISHING", risk)
    if risk >= 40:
        return ("SUSPICIOUS", risk)
    return ("SAFE", risk)


def load_sms():
    data = []
    with open("/tmp/sms-spam/SMSSpamCollection") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            label, _, msg = line.partition("\t")
            data.append((label.strip(), msg))
    return data


if __name__ == "__main__":
    import random
    sms = load_sms()
    print(f"sms: {len(sms)} ({sum(1 for l, _ in sms if l=='spam')} spam)")
    random.seed(7)
    sample = random.sample(sms, 1500)
    tp = tn = fp = fn = 0
    for label, msg in sample:
        pred, _ = analyze_text(msg)
        flagged = pred in ("PHISHING", "SUSPICIOUS")
        if label == "spam" and flagged: tp += 1
        elif label == "ham" and not flagged: tn += 1
        elif flagged: fp += 1
        else: fn += 1
    n = len(sample)
    print(f"BASELINE sms-1500: acc={(tp+tn)/n:.4f} prec={tp/(tp+fp):.4f} rec={tp/(tp+fn):.4f} "
          f"(TP={tp} TN={tn} FP={fp} FN={fn})")
