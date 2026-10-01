#!/usr/bin/env python3
"""GillNet accuracy test part 2: message scanner, password meter, chat.
Uses curl (robust against the flaky VM->Render path). URL results are
parsed from the part-1 log."""
import json, random, re, subprocess, time

BASE = "https://gillnet-backend-recovery.onrender.com"

def curl_post(path, body, token=None, retries=5):
    data = json.dumps(body)
    for a in range(retries):
        cmd = ["curl", "-s", "--max-time", "90", "-w", "\n%{http_code}",
               "-X", "POST", BASE + path, "-H", "Content-Type: application/json"]
        if token:
            cmd += ["-H", "Authorization: Bearer " + token]
        cmd += ["-d", data]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=100).stdout
            payload, _, code = out.rpartition("\n")
            code = code.strip()
            if code.startswith("2"):
                return 200, json.loads(payload or "{}")
            print(f"  [attempt {a+1} {path}: http {code}]", flush=True)
        except Exception as e:
            print(f"  [attempt {a+1} {path}: {type(e).__name__}]", flush=True)
        time.sleep(2 + a * 2)
    raise RuntimeError("failed: " + path)

def curl_get(path, token):
    cmd = ["curl", "-s", "--max-time", "60", BASE + path,
           "-H", "Authorization: Bearer " + token]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=70).stdout
    return json.loads(out)

# fresh user
email = f"accuracy2-{int(time.time())}@gillnet.test"
st, reg = curl_post("/api/auth/register",
    {"name": "Accuracy Test", "email": email, "password": "AccuracyTest#2026"})
token = reg["token"]
print("user:", email, "| credits:", curl_get("/api/auth/me", token)["credits"], flush=True)

results = {"url": [], "message": [], "password": [], "chat": []}

# ---- recover URL results from part-1 log ----
log = open("/tmp/accuracy_run.log").read()
for m in re.finditer(r"URL \[(LEGIT|PHISH)\] -> (SAFE|PHISHING)\s+(OK|MISS)\s+(\S+)", log):
    truth, pred, verdict, url = m.groups()
    results["url"].append({"url": url, "truth": truth, "pred": pred,
                           "ok": verdict == "OK", "status": 200})
print(f"recovered {len(results['url'])} URL results from part-1 log", flush=True)

# ---- message scanner ----
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
random.seed(42)
msg_cases = [(m, "LEGIT") for m in genuine] + [(m, "PHISH") for m in phishing]
random.shuffle(msg_cases)
for msg, truth in msg_cases:
    st, resp = curl_post("/api/message/analyze", {"message": msg}, token)
    cls = (resp.get("classification") or "?").upper()
    ok = (cls == "SAFE" and truth == "LEGIT") or (cls in ("SUSPICIOUS", "SCAM") and truth == "PHISH")
    results["message"].append({"msg": msg, "truth": truth, "class": cls,
        "score": resp.get("riskScore"), "indicators": resp.get("indicators"), "ok": ok, "status": st})
    print(f"MSG [{truth:5s}] -> {cls:10s} ({resp.get('riskScore')}) {'OK ' if ok else 'MISS'} {msg[:55]}", flush=True)
    time.sleep(1)

# ---- password meter (no auth) ----
weak = ["123456", "password", "qwerty", "letmein", "abc123", "111111",
        "dragon", "football", "admin123", "welcome1"]
random.seed(7)
alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*"
strong = [''.join(random.choice(alphabet) for _ in range(20)) for _ in range(10)]
for pw, truth in [(p, "WEAK") for p in weak] + [(p, "STRONG") for p in strong]:
    st, resp = curl_post("/api/password/analyze", {"password": pw})
    strength = (resp.get("strength") or "?").upper()
    ok = (truth == "WEAK" and strength in ("WEAK", "FAIR")) or \
         (truth == "STRONG" and strength in ("STRONG", "VERY_STRONG", "GOOD"))
    results["password"].append({"pw": pw if truth == "WEAK" else "***strong***",
        "truth": truth, "strength": strength, "score": resp.get("score"),
        "entropy": resp.get("entropy"), "crack": resp.get("estimatedCrackTime"),
        "isCommon": resp.get("isCommon"), "ok": ok})
    print(f"PW  [{truth:6s}] -> {strength:10s} score={resp.get('score')} common={resp.get('isCommon')} {'OK ' if ok else 'MISS'}", flush=True)
    time.sleep(0.5)

# ---- chat smoke test ----
st, resp = curl_post("/api/chat",
    {"message": "How can I tell if an email asking for my bank OTP is a scam?"}, token)
reply = resp.get("reply", "") or ""
results["chat"].append({"status": st, "category": resp.get("category"),
                        "reply_len": len(reply), "reply": reply})
print("CHAT status:", st, "| category:", resp.get("category"), flush=True)
print("CHAT reply:", reply[:300].replace("\n", " "), flush=True)

print("credits left:", curl_get("/api/auth/me", token)["credits"], flush=True)
json.dump(results, open("/home/hatch/workspace/gillnet-project/accuracy-results.json", "w"), indent=1)

def metrics(items, pos=("PHISH", "STRONG"), neg=("LEGIT", "WEAK")):
    tp = sum(1 for i in items if i["ok"] and i["truth"] in pos)
    tn = sum(1 for i in items if i["ok"] and i["truth"] in neg)
    fp = sum(1 for i in items if not i["ok"] and i["truth"] in neg)
    fn = sum(1 for i in items if not i["ok"] and i["truth"] in pos)
    n = len(items)
    return ((tp + tn) / n if n else 0, tp / (tp + fp) if tp + fp else 0,
            tp / (tp + fn) if tp + fn else 0, tp, tn, fp, fn)

for name in ("url", "message", "password"):
    acc, prec, rec, tp, tn, fp, fn = metrics(results[name])
    print(f"\n{name.upper()}: acc={acc:.1%} prec={prec:.1%} rec={rec:.1%} "
          f"(TP={tp} TN={tn} FP={fp} FN={fn} n={len(results[name])})")
print("\nMISSES:")
for name in ("url", "message", "password"):
    for i in results[name]:
        if not i["ok"]:
            key = i.get("url") or (i.get("msg") or "")[:80] or i.get("pw")
            print(f"  {name}: [{i['truth']}] -> {i.get('pred') or i.get('class') or i.get('strength')} | {key}")
print("DONE")
