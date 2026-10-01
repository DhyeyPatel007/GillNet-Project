#!/usr/bin/env python3
"""GillNet live production accuracy test: URL scanner, message scanner,
password strength meter, chat assistant. Runs against the live Render backend."""
import csv, json, random, time, urllib.request

BASE = "https://gillnet-backend-recovery.onrender.com"
random.seed(42)

def _do_post(path, body, token):
    req = urllib.request.Request(BASE + path,
        data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json",
                 **({"Authorization": "Bearer " + token} if token else {})})
    with urllib.request.urlopen(req, timeout=90) as r:
        return r.status, json.loads(r.read().decode())

def post(path, body, token=None):
    for attempt in range(6):
        try:
            return _do_post(path, body, token)
        except urllib.error.HTTPError as e:
            try: return e.code, json.loads(e.read().decode())
            except Exception: return e.code, {"error": str(e)}
        except Exception as e:
            print(f"  [retry {attempt+1} {path}: {type(e).__name__}]", flush=True)
            time.sleep(3 * (attempt + 1))
    raise RuntimeError("POST failed after retries: " + path)

def get(path, token):
    for attempt in range(6):
        try:
            req = urllib.request.Request(BASE + path,
                headers={"Authorization": "Bearer " + token})
            with urllib.request.urlopen(req, timeout=90) as r:
                return json.loads(r.read().decode())
        except Exception as e:
            print(f"  [retry {attempt+1} GET {path}: {type(e).__name__}]", flush=True)
            time.sleep(3 * (attempt + 1))
    raise RuntimeError("GET failed after retries: " + path)

# ---------- 0. fresh test user ----------
email = f"accuracy-{int(time.time())}@gillnet.test"
st, reg = post("/api/auth/register", {"name": "Accuracy Test", "email": email, "password": "AccuracyTest#2026"})
token = reg["token"]
print("user:", email, "| credits:", get("/api/auth/me", token)["credits"], flush=True)

results = {"url": [], "message": [], "password": [], "chat": []}

# ---------- 1. URL scanner: 10 legit + 10 phishing, seeded from labeled 20k ----------
rows = list(csv.DictReader(open("/home/hatch/workspace/gillnet-project/GillNet-AI-Backend/ml-service/phishing_20k_real.csv")))
legit = random.sample([r for r in rows if r["Label"] == "1"], 10)
phish = random.sample([r for r in rows if r["Label"] == "-1"], 10)
url_cases = [(u["URL"], "LEGIT") for u in legit] + [(u["URL"], "PHISH") for u in phish]
random.shuffle(url_cases)
for url, truth in url_cases:
    st, resp = post("/api/url/analyze", {"url": url}, token)
    pred = (resp.get("prediction") or resp.get("verdict") or "?").upper()
    ok = (pred == "SAFE" and truth == "LEGIT") or (pred == "PHISHING" and truth == "PHISH")
    results["url"].append({"url": url, "truth": truth, "pred": pred, "ok": ok, "status": st})
    print(f"URL [{truth:5s}] -> {pred:8s} {'OK ' if ok else 'MISS'} {url[:70]}", flush=True)
    time.sleep(0.4)

# ---------- 2. Message scanner: 10 genuine + 10 real-world phishing lures ----------
genuine = [
 "Hi Priya, I'll be home for dinner on Sunday. Can you pick up some milk on your way? Love, Mom",
 "Reminder: Your dentist appointment is tomorrow at 10:30 AM. Reply YES to confirm or call us to reschedule.",
 "Your monthly bank statement for September is now available. Log in to your mobile banking app to view it.",
 "Meeting rescheduled: the project sync has moved to Thursday at 3 PM in Conference Room B. The agenda is attached.",
 "Your flight AI-202 check-in is now open. Boarding begins 45 minutes before departure. Please keep your ID ready.",
 "Thanks for subscribing to our newsletter! Here are this week's top stories in cybersecurity.",
 "Your password was successfully changed. If you did not make this change, please contact support immediately.",
 "Your subscription renews on October 15 at $9.99 per month. You can manage or cancel anytime in your account settings.",
 "The package you ordered has shipped and will arrive on Thursday. You can follow its journey in the delivery app.",
 "Happy birthday! Hope you have a wonderful day. Dinner is on me this weekend. - Rahul",
]
phishing = [
 "Your PayPal account has been limited due to unusual activity. Verify your identity within 24 hours or it will be permanently suspended: http://paypal-verify-login.tk/signin",
 "We detected unauthorized access to your Apple ID and your account has been locked. Verify immediately: bit.ly/verify-apple",
 "Dear customer, your bank account will be blocked today. To keep it active, please share the OTP you receive with our support agent on this call.",
 "CONGRATULATIONS! You have won $2,500,000 in the Global Lottery draw. Pay a $250 processing fee by wire transfer to claim your prize.",
 "You are eligible for a tax refund of $1,284. Submit your bank details within 48 hours to receive it: http://irs-refund-claim.top/apply",
 "Hi, this is your CEO. I am stuck in meetings all day. Please buy five $100 gift cards, scratch the backs, and text me photos of the codes. This is urgent.",
 "Your parcel could not be delivered. A redelivery fee of $2.99 is required: https://dhl-express-delivery.club/pay",
 "You have been selected to receive a $5,000 cash prize! Claim your prize now by paying a small $49 verification fee.",
 "Security Alert: your crypto wallet will be deactivated in 12 hours. Enter your 12-word seed phrase at http://wallet-verify-online.xyz/restore to keep access.",
 "IT Department: your password expires today. Click here to retain your current password: http://intranet-password-reset.pw/keep",
]
msg_cases = [(m, "LEGIT") for m in genuine] + [(m, "PHISH") for m in phishing]
random.shuffle(msg_cases)
for msg, truth in msg_cases:
    st, resp = post("/api/message/analyze", {"message": msg}, token)
    cls = (resp.get("classification") or "?").upper()
    ok = (cls == "SAFE" and truth == "LEGIT") or (cls in ("SUSPICIOUS", "SCAM") and truth == "PHISH")
    results["message"].append({"msg": msg[:60], "truth": truth, "class": cls,
        "score": resp.get("riskScore"), "ok": ok, "status": st})
    print(f"MSG [{truth:5s}] -> {cls:10s} ({resp.get('riskScore')}) {'OK ' if ok else 'MISS'} {msg[:55]}", flush=True)
    time.sleep(0.4)

# ---------- 3. Password meter: 10 weak + 10 strong (no auth needed) ----------
weak = ["123456", "password", "qwerty", "letmein", "abc123", "111111",
        "dragon", "football", "admin123", "welcome1"]
random.seed(7)
strong = [''.join(random.choice("abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*") for _ in range(20)) for _ in range(10)]
for pw, truth in [(p, "WEAK") for p in weak] + [(p, "STRONG") for p in strong]:
    st, resp = post("/api/password/analyze", {"password": pw})
    strength = (resp.get("strength") or "?").upper()
    ok = (truth == "WEAK" and strength in ("WEAK", "FAIR")) or \
         (truth == "STRONG" and strength in ("STRONG", "VERY_STRONG", "GOOD"))
    results["password"].append({"pw": pw if truth == "WEAK" else "***strong***",
        "truth": truth, "strength": strength, "score": resp.get("score"),
        "isCommon": resp.get("isCommon"), "ok": ok})
    print(f"PW  [{truth:6s}] -> {strength:10s} score={resp.get('score')} common={resp.get('isCommon')} {'OK ' if ok else 'MISS'}", flush=True)
    time.sleep(0.2)

# ---------- 4. Chat smoke test ----------
st, resp = post("/api/chat", {"message": "How can I tell if an email asking for my bank OTP is a scam?"}, token)
reply = resp.get("reply", "")
results["chat"].append({"status": st, "category": resp.get("category"),
                        "reply_len": len(reply), "reply_head": reply[:160]})
print("CHAT status:", st, "| category:", resp.get("category"), "| reply:", reply[:160].replace("\n", " "), flush=True)

print("credits left:", get("/api/auth/me", token)["credits"], flush=True)
json.dump(results, open("/home/hatch/workspace/gillnet-project/accuracy-results.json", "w"), indent=1)

def metrics(items):
    tp = sum(1 for i in items if i["ok"] and i["truth"] in ("PHISH", "STRONG"))
    tn = sum(1 for i in items if i["ok"] and i["truth"] in ("LEGIT", "WEAK"))
    fp = sum(1 for i in items if not i["ok"] and i["truth"] in ("LEGIT", "WEAK"))
    fn = sum(1 for i in items if not i["ok"] and i["truth"] in ("PHISH", "STRONG"))
    n = len(items)
    acc = (tp + tn) / n if n else 0
    prec = tp / (tp + fp) if tp + fp else 0
    rec = tp / (tp + fn) if tp + fn else 0
    return acc, prec, rec, tp, tn, fp, fn

for name in ("url", "message", "password"):
    acc, prec, rec, tp, tn, fp, fn = metrics(results[name])
    print(f"\n{name.upper()}: acc={acc:.1%} prec={prec:.1%} rec={rec:.1%} "
          f"(TP={tp} TN={tn} FP={fp} FN={fn} n={len(results[name])})")
print("\nmisses:")
for name in ("url", "message", "password"):
    for i in results[name]:
        if not i["ok"]:
            key = i.get("url") or i.get("msg") or i.get("pw")
            print(f"  {name}: [{i['truth']}] -> {i.get('pred') or i.get('class') or i.get('strength')} | {key}")
