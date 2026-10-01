#!/usr/bin/env python3
"""Accuracy test for the dashboard's Phishing Scanner endpoints:
  - /api/phishing/analyze-text   (Text tab)
  - /api/phishing/analyze-image  (Screenshot tab)
Screenshots are rendered from the same 20 message texts with realistic
OS-style filenames, sent exactly like the UI sends them
(base64 data URL + extractedText from browser OCR)."""
import base64, io, json, random, subprocess, textwrap, time

BASE = "https://gillnet-backend-recovery.onrender.com"

def curl_post(path, body, token=None, retries=5):
    data = json.dumps(body)
    for a in range(retries):
        cmd = ["curl", "-s", "--max-time", "120", "-w", "\n%{http_code}",
               "-X", "POST", BASE + path, "-H", "Content-Type: application/json"]
        if token:
            cmd += ["-H", "Authorization: Bearer " + token]
        cmd += ["-d", data]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=130).stdout
            payload, _, code = out.rpartition("\n")
            code = code.strip()
            if code.startswith("2"):
                return int(code), json.loads(payload or "{}")
            print(f"  [attempt {a+1} {path}: http {code}]", flush=True)
        except Exception as e:
            print(f"  [attempt {a+1} {path}: {type(e).__name__}]", flush=True)
        time.sleep(2 + a * 2)
    raise RuntimeError("failed: " + path)

def curl_get(path, token):
    cmd = ["curl", "-s", "--max-time", "60", BASE + path,
           "-H", "Authorization: Bearer " + token]
    return json.loads(subprocess.run(cmd, capture_output=True, text=True, timeout=70).stdout)

# ---------- user ----------
email = f"phishacc-{int(time.time())}@gillnet.test"
st, reg = curl_post("/api/auth/register",
    {"name": "Phish Accuracy", "email": email, "password": "PhishTest#2026"})
token = reg["token"]
print("user:", email, "| credits:", curl_get("/api/auth/me", token)["credits"], flush=True)

# ---------- shared 20 texts ----------
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
cases = [(m, "LEGIT") for m in genuine] + [(m, "PHISH") for m in phishing]
random.shuffle(cases)

results = {"phish_text": [], "phish_image": [], "probes": []}

def detected(level):
    return level in ("SUSPICIOUS", "PHISHING")

# ---------- 1. analyze-text (dashboard Text tab) ----------
for msg, truth in cases:
    st, resp = curl_post("/api/phishing/analyze-text",
        {"content": msg, "fileName": None}, token)
    lvl = (resp.get("threatLevel") or "?").upper()
    ok = (lvl == "SAFE" and truth == "LEGIT") or (detected(lvl) and truth == "PHISH")
    results["phish_text"].append({"msg": msg, "truth": truth, "level": lvl,
        "score": resp.get("riskScore"), "ok": ok})
    print(f"TEXT  [{truth:5s}] -> {lvl:10s} ({resp.get('riskScore')}) {'OK ' if ok else 'MISS'} {msg[:50]}", flush=True)
    time.sleep(1)

# ---------- 2. analyze-image (dashboard Screenshot tab) ----------
from PIL import Image, ImageDraw

def render_screenshot(text, idx):
    img = Image.new("RGB", (900, 420), "white")
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, 900, 48], fill=(24, 38, 72))
    d.text((20, 14), "Message", fill="white")
    y = 70
    for line in textwrap.wrap(text, width=72):
        d.text((24, y), line, fill=(20, 20, 20))
        y += 26
    d.text((24, 380), f"screenshot_{idx}", fill=(150, 150, 150))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()

for i, (msg, truth) in enumerate(cases):
    data_url = render_screenshot(msg, i)
    # realistic OS screenshot filename, as a real user upload would have
    fname = f"Screenshot 2026-10-01 at 09.{40 + (i % 20):02d}.{(i * 7) % 60:02d}.png"
    st, resp = curl_post("/api/phishing/analyze-image",
        {"content": data_url, "fileName": fname, "extractedText": msg}, token)
    lvl = (resp.get("threatLevel") or "?").upper()
    ok = (lvl == "SAFE" and truth == "LEGIT") or (detected(lvl) and truth == "PHISH")
    results["phish_image"].append({"truth": truth, "file": fname, "level": lvl,
        "score": resp.get("riskScore"),
        "extractedTextEcho": bool(resp.get("extractedText")), "ok": ok})
    print(f"IMAGE [{truth:5s}] -> {lvl:10s} ({resp.get('riskScore')}) {'OK ' if ok else 'MISS'} {fname}", flush=True)
    time.sleep(1)

# ---------- 3. filename probes: same phishing pixels, different names ----------
phish_img = render_screenshot(phishing[0], 99)
for fname in ["paypal-login-screenshot.png", "timetable-class-schedule.png",
              "Screenshot 2026-10-01 at 10.00.00.png"]:
    st, resp = curl_post("/api/phishing/analyze-image",
        {"content": phish_img, "fileName": fname, "extractedText": phishing[0]}, token)
    lvl = (resp.get("threatLevel") or "?").upper()
    results["probes"].append({"file": fname, "level": lvl, "score": resp.get("riskScore")})
    print(f"PROBE {fname} -> {lvl} ({resp.get('riskScore')})", flush=True)
    time.sleep(1)

print("credits left:", curl_get("/api/auth/me", token)["credits"], flush=True)
json.dump(results, open("/home/hatch/workspace/gillnet-project/accuracy-phishing.json", "w"), indent=1)

def metrics(items):
    tp = sum(1 for i in items if i["ok"] and i["truth"] == "PHISH")
    tn = sum(1 for i in items if i["ok"] and i["truth"] == "LEGIT")
    fp = sum(1 for i in items if not i["ok"] and i["truth"] == "LEGIT")
    fn = sum(1 for i in items if not i["ok"] and i["truth"] == "PHISH")
    n = len(items)
    return ((tp + tn) / n if n else 0, tp / (tp + fp) if tp + fp else 0,
            tp / (tp + fn) if tp + fn else 0, tp, tn, fp, fn)

for name in ("phish_text", "phish_image"):
    acc, prec, rec, tp, tn, fp, fn = metrics(results[name])
    print(f"\n{name.upper()}: acc={acc:.1%} prec={prec:.1%} rec={rec:.1%} "
          f"(TP={tp} TN={tn} FP={fp} FN={fn} n={len(results[name])})")
print("\nMISSES:")
for name in ("phish_text", "phish_image"):
    for i in results[name]:
        if not i["ok"]:
            key = (i.get("msg") or i.get("file") or "")[:70]
            print(f"  {name}: [{i['truth']}] -> {i['level']} | {key}")
print("DONE")
