#!/usr/bin/env python3
"""NB-hybrid experiment: rule layer + naive-bayes word log-odds trained on
SMS tune split. If held-out improves with precision intact, ship it."""
import re, math, random
from collections import Counter
from text_v4 import analyze_text_v4, load_sms

sms = load_sms()
random.seed(42)
random.shuffle(sms)
tune, held = sms[:3000], sms[3000:]

def words(t):
    return re.findall(r"[a-z']{2,}", t.lower())

spam_c, ham_c = Counter(), Counter()
ns = nh = 0
for label, msg in tune:
    ws = set(words(msg))
    if label == "spam":
        ns += 1
        spam_c.update(ws)
    else:
        nh += 1
        ham_c.update(ws)

V = set(spam_c) | set(ham_c)
logodds = {}
for w in V:
    ps = (spam_c[w] + 1) / (ns + 2)
    ph = (ham_c[w] + 1) / (nh + 2)
    logodds[w] = math.log(ps / ph)

def nb_score(text):
    return sum(logodds.get(w, 0) for w in set(words(text)))

# tune threshold on tune split: only applied when rules say SAFE (risk<40)
def hybrid(text, thr):
    pred, risk = analyze_text_v4(text)
    if pred == "SAFE" and nb_score(text) >= thr:
        return ("SUSPICIOUS", 45)
    return (pred, risk)

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

best = (0, None)
for thr in [3, 4, 5, 6, 8, 10]:
    a, p, r = bench(lambda t: hybrid(t, thr), tune)
    print(f"thr={thr} tune acc={a:.4f} prec={p:.4f} rec={r:.4f}")
    if a > best[0]:
        best = (a, thr)
print("best:", best)
for name, split in (("TUNE", tune), ("HELD", held)):
    a, p, r = bench(lambda t: hybrid(t, best[1]), split)
    print(f"hybrid {name}: acc={a:.4f} prec={p:.4f} rec={r:.4f}")
