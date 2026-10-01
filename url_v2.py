#!/usr/bin/env python3
"""v2 URL heuristic: full UCI-style feature set, tuned on split A,
reported on held-out split B."""
import csv, random, re, itertools
from urllib.parse import urlparse

random.seed(1234)
rows = list(csv.DictReader(open(
    "/home/hatch/workspace/gillnet-project/GillNet-AI-Backend/ml-service/phishing_20k_real.csv")))
random.shuffle(rows)
A, B = rows[:10000], rows[10000:]

SHORTENERS = ["bit.ly", "tinyurl.", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
              "adf.ly", "j.mp", "cutt.ly", "shorte.st", "tiny.cc", "rb.gy",
              "shorturl.", "lnkd.in", "fb.me", "bitly.", "t.ly"]
SUSP_TLDS = [".tk", ".xyz", ".top", ".club", ".online", ".site", ".buzz", ".cf",
             ".gq", ".ml", ".pw", ".rest", ".fit", ".lol", ".cam", ".quest",
             ".zip", ".mov", ".monster", ".click", ".link", ".work", ".gdn",
             ".bid", ".win", ".stream", ".trade", ".review", ".date", ".faith",
             ".cricket", ".science", ".party", ".loan", ".download", ".country",
             ".stream"]
PATH_KWS = ["login", "signin", "sign-in", "verify", "verification", "secure",
            "account", "update", "confirm", "banking", "wallet", "credential",
            "password", "ebayisapi", "webscr", "authenticate", "oauth"]
HOST_KWS = ["login", "verify", "secure", "banking", "update", "paypal", "account",
            "wallet", "signin", "confirm"]

def features(url):
    f = {}
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
        if not p.hostname:
            raise ValueError
        f["host"] = host
        f["ip"] = bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host))
        f["long"] = len(url) > 75
        f["at"] = "@" in url
        f["hyphen"] = "-" in host
        f["dots"] = host.count(".") > 2
        f["http"] = not url.lower().startswith("https://")
        f["host_kw"] = any(k in host for k in HOST_KWS)
        f["shortener"] = any(s in host for s in SHORTENERS)
        f["susp_tld"] = any(host.endswith(t) for t in SUSP_TLDS)
        f["puny"] = "xn--" in host
        after = url.split("://", 1)[1] if "://" in url else url
        f["dblslash"] = "//" in after
        try:
            f["port"] = p.port is not None and p.port not in (80, 443)
        except ValueError:
            f["port"] = True
        f["digits"] = sum(c.isdigit() for c in host) >= 4
        f["path_kw"] = any(k in (p.path or "").lower() for k in PATH_KWS)
        f["long_host"] = len(host) > 30
        h = host
        f["edu_gov"] = (h.endswith(".gov") or ".gov." in h or h.endswith(".edu")
                        or ".edu." in h or ".ac." in h)
        f["parse_fail"] = False
    except Exception:
        f = {"parse_fail": True, "edu_gov": False}
    return f

def v2(url, W, thr):
    f = features(url)
    if f.get("parse_fail"):
        return ("PHISHING", 80)
    s = 15
    s += W["ip"] if f["ip"] else 0
    s += W["long"] if f["long"] else 0
    s += W["at"] if f["at"] else 0
    if f["hyphen"] and not f["edu_gov"]:
        s += W["hyphen"]
    s += W["dots"] if f["dots"] else 0
    s += W["http"] if f["http"] else 0
    s += W["host_kw"] if f["host_kw"] else 0
    s += W["shortener"] if f["shortener"] else 0
    s += W["susp_tld"] if f["susp_tld"] else 0
    s += W["puny"] if f["puny"] else 0
    s += W["dblslash"] if f["dblslash"] else 0
    s += W["port"] if f["port"] else 0
    s += W["digits"] if f["digits"] else 0
    s += W["path_kw"] if f["path_kw"] else 0
    s += W["long_host"] if f["long_host"] else 0
    if f["edu_gov"]:
        s = min(s, 10)   # whitelist applied LAST
    s = min(100, max(0, s))
    return ("PHISHING" if s >= thr else "SAFE", s)

def acc(fn, split):
    ok = sum(1 for r in split
             if (fn(r["URL"])[0] == "PHISHING") == (r["Label"] == "-1"))
    return ok / len(split)

W = dict(ip=40, long=15, at=25, hyphen=15, dots=20, http=20, host_kw=20,
         shortener=25, susp_tld=20, puny=30, dblslash=25, port=20,
         digits=25, path_kw=20, long_host=15)
best = (0, None)
for thr in (45, 50, 55, 60):
    a = acc(lambda u: v2(u, W, thr), A)
    print(f"thr={thr} tune_acc={a:.4f}", flush=True)
    if a > best[0]:
        best = (a, thr)
print("best thr on tune:", best, flush=True)

import json
json.dump({"W": W, "thr": best[1]},
          open("/home/hatch/workspace/gillnet-project/url_v2_params.json", "w"))
for name, split in (("TUNE", A), ("HELDOUT", B)):
    a = acc(lambda u: v2(u, W, best[1]), split)
    print(f"v2 {name}: acc={a:.4f}", flush=True)
