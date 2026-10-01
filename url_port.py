#!/usr/bin/env python3
"""Fidelity port of UrlScanService.evaluateHeuristicFallback (Java) for
rapid iteration. Tune on split A, report on held-out split B."""
import csv, random, re
from urllib.parse import urlparse

random.seed(1234)
rows = list(csv.DictReader(open(
    "/home/hatch/workspace/gillnet-project/GillNet-AI-Backend/ml-service/phishing_20k_real.csv")))
random.shuffle(rows)
A, B = rows[:10000], rows[10000:]
print(f"tune={len(A)} heldout={len(B)}", flush=True)

PIRACY = ["net77.cc", "123movies", "fmovies", "soap2day", "putlocker",
          "solarmovie", "lookmovie", "yify", "thepiratebay", "rarbg", "kickass"]
KEYWORDS = ["login", "verify", "secure", "banking", "update", "paypal", "account", "wallet"]

def java_port(url):
    """Exact port of the current Java heuristic. Returns (prediction, score)."""
    risk = 15
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
        if not p.hostname:
            raise ValueError("no host")
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host):
            risk += 40
        if len(url) > 75:
            risk += 15
        if "@" in url:
            risk += 25
        for bad in PIRACY:
            if bad in host:
                risk += 70
                break
        edu_gov = host.endswith((".edu", ".ac.in", ".edu.in", ".gov", ".gov.in"))
        if "-" in host and not edu_gov:
            risk += 15
        if edu_gov:
            risk = min(risk, 10)
        if host.count(".") > 2:
            risk += 20
        if not url.lower().startswith("https://"):
            risk += 20
        for kw in KEYWORDS:
            if kw in url.lower() and (kw + ".com") not in host:
                risk += 20
                break
    except Exception:
        risk += 30
    risk = min(100, max(0, risk))
    return ("PHISHING" if risk >= 50 else "SAFE", risk)

def measure(fn_, split):
    tp = tn = fp = fn = 0
    for r in split:
        pred, _ = fn_(r["URL"])
        truth = "PHISH" if r["Label"] == "-1" else "LEGIT"
        if pred == "PHISHING" and truth == "PHISH": tp += 1
        elif pred == "SAFE" and truth == "LEGIT": tn += 1
        elif pred == "PHISHING": fp += 1
        else: fn += 1
    n = len(split)
    return (tp + tn) / n, tp / (tp + fp) if tp + fp else 0, tp / (tp + fn) if tp + fn else 0, tp, tn, fp, fn

for name, split in (("TUNE", A), ("HELDOUT", B)):
    acc, prec, rec, tp, tn, fp, fn = measure(java_port, split)
    print(f"java-port {name}: acc={acc:.2%} prec={prec:.2%} rec={rec:.2%} "
          f"(TP={tp} TN={tn} FP={fp} FN={fn})", flush=True)
