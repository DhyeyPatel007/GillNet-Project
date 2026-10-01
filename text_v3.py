#!/usr/bin/env python3
"""v2 text heuristic: prize-lure coverage, accumulating harvesting signals,
premium-rate callback detection. Tune on SMS-3000, report on SMS-2574 held-out."""
import re, random
from text_port import (load_sms, analyze_text as v1, TARGET_BRANDS,
                       URGENCY_TRIGGERS as U1, HARVESTING_TRIGGERS as H1,
                       URL_RE, EMAIL_RE)
from url_v4 import v4 as url_v4
import json
P = json.load(open("/home/hatch/workspace/gillnet-project/url_v4_params.json"))
UW, UTHR = P["W"], P["thr"]

U2 = U1 + [
    "congratulations", "congrats", "you have won", "you've won", "have won",
    "won the", "winner", "lottery", "prize", "award", "claim your", "claim now",
    "to claim", "selected to receive", "lucky day", "await collection",
    "awaiting collection", "free entry", "free gift", "free ringtone",
    "cash prize", "cash-balance", "txt to", "text to", "reply to claim",
    "call now", "call today",
    "win \u00a3", "win a", "chance to win", "to win", "weekly quiz", "wkly",
    "freemsg", "free msg", "ringtone", "polyphonic", "dating service", "chatline",
    "strong-buy", "explosive pick", "un-redeemed", "entitled to", "sexy",
    "txtin", "hardcore",
]
H2 = H1 + [
    "otp", "one-time password", "verification code", "gift card",
    "wire transfer", "processing fee", "claim your prize", "bank details",
    "account details", "card details", "premium rate", "secret admirer",
    "cash-in", "charged", "p/min", "per min",
]
PREMIUM_RE = re.compile(r"premium\s*rate|\b09\d{8,}\b|\b087[01]\d{6,}\b|\b084[45]\d{6,}\b", re.I)
SHORTCODE_RE = re.compile(r"\b(txt|text|send)\b[\w\s:]{0,30}\bto\s+\d{4,6}\b", re.I)


def analyze_text_v3(text, harvest_cap=50):
    lower = text.lower()
    risk = 10
    detected_brand = None
    sender_spoofed = False
    urgency_hits = []
    harvest_hits = []

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
        uu = u if u.startswith(("http://", "https://")) else "http://" + u
        pred, score = url_v4(uu, UW, UTHR)
        if pred == "PHISHING" or score >= 60:
            malicious += 1
            risk = max(risk + 40, 90)

    for brand in TARGET_BRANDS:
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
    for t in U2:
        if t in lower:
            urgency_hits.append(t)
            risk += 12
    harvest_score = 0
    for t in H2:
        if t in lower:
            harvest_hits.append(t)
            harvest_score += 20
    risk += min(harvest_score, harvest_cap)
    if PREMIUM_RE.search(text):
        risk += 25
        harvest_hits.append("premium-rate callback")
    if SHORTCODE_RE.search(text):
        risk += 25
        harvest_hits.append("premium shortcode CTA")
    if any(w in lower for w in ("win", "won", "prize", "award")) and any(
            w in lower for w in ("call", "txt", "claim", "text ")):
        risk += 20
        urgency_hits.append("prize+callback combo")
    risk = min(100, max(5, risk))
    if malicious > 0:
        return ("PHISHING", max(risk, 90))
    if risk >= 70 or sender_spoofed or (harvest_hits and urgency_hits):
        return ("PHISHING", risk)
    if risk >= 40:
        return ("SUSPICIOUS", risk)
    return ("SAFE", risk)


CURATED = [
    # (text, expect_flagged)
    ("Your OTP for login is 482913. Do not share it with anyone. Valid for 10 minutes.", False),
    ("Team standup moved to 10:30 AM tomorrow in conference room B. Agenda: sprint review.", False),
    ("Your monthly bank statement is ready to view in the mobile app.", False),
    ("Reminder: dentist appointment on Friday at 4 PM. Reply C to confirm.", False),
    ("Your password was successfully changed. If this wasn't you, contact support.", False),
    ("Class timetable: Monday Math 9AM Room 201, Tuesday Physics 11AM Room 105.", False),
    ("Your order #48291 has shipped. Track it here: https://amazon.com/track/48291", False),
    ("Mom: Can you pick up groceries on your way home? Milk, eggs, bread.", False),
    ("Meeting notes from today are uploaded to the shared drive.", False),
    ("Happy birthday! Hope you have a wonderful day.", False),
    ("CONGRATULATIONS! You have won $2,500,000 in the International Lottery Draw. To claim your prize, pay a $500 processing fee via wire transfer within 48 hours.", True),
    ("Dear employee, the CEO requests you purchase $2000 in gift cards and send the codes immediately. This is urgent and confidential.", True),
    ("Your bank account has been temporarily blocked due to suspicious activity. To unblock, share the OTP sent to your phone with our support agent on this call.", True),
    ("You have received a cash prize of $5000! Click the link to claim your prize now, just pay a small verification fee.", True),
    ("Your parcel could not be delivered. Pay the $2.99 redelivery fee here: https://dhl-express-delivery.club/pay", True),
    ("URGENT: Your PayPal account has been limited. Verify your identity now: http://paypal-secure-login.tk/verify", True),
    ("Security alert: someone accessed your Apple ID from a new device. If this wasn't you, reset your password: http://apple-id-reset.xyz", True),
    ("You won a free iPhone! Claim within 24 hours: http://free-iphone-winner.club/claim", True),
    ("Final notice: your Netflix subscription payment failed. Update billing info: http://netflix-billing-update.top", True),
    ("HR: your employment will be terminated unless you provide your login credentials within 24 hours.", True),
]


def bench(fn, data):
    tp = tn = fp = fn_ = 0
    for label, msg in data:
        pred, _ = fn(msg)
        flagged = pred in ("PHISHING", "SUSPICIOUS")
        if label == "spam" and flagged: tp += 1
        elif label == "ham" and not flagged: tn += 1
        elif flagged: fp += 1
        else: fn_ += 1
    n = len(data)
    return (tp + tn) / n, tp / (tp + fp) if tp + fp else 0, tp / (tp + fn_) if tp + fn_ else 0


if __name__ == "__main__":
    sms = load_sms()
    random.seed(42)
    random.shuffle(sms)
    tune, held = sms[:3000], sms[3000:]
    print(f"tune={len(tune)} held={len(held)}")
    for name, fn in (("v1", v1), ("v3", analyze_text_v3)):
        for sname, split in (("TUNE", tune), ("HELD", held)):
            a, p, r = bench(fn, split)
            print(f"{name} {sname}: acc={a:.4f} prec={p:.4f} rec={r:.4f}")
    print("curated-20 v3:", sum(
        1 for t, exp in CURATED
        if (analyze_text_v3(t)[0] in ("PHISHING", "SUSPICIOUS")) == exp), "/20")
