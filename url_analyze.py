#!/usr/bin/env python3
"""Analyze java-port misses on tune split; test candidate features."""
import csv, random, re
from urllib.parse import urlparse
from url_port import java_port, A

SHORTENERS = ["bit.ly", "tinyurl.", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
              "adf.ly", "j.mp", "cutt.ly", "shorte.st", "tiny.cc", "rb.gy", "s.id",
              "shorturl.", "lnkd.in", "fb.me"]
SUSP_TLDS = [".tk", ".xyz", ".top", ".club", ".online", ".site", ".buzz", ".cf",
             ".gq", ".ml", ".pw", ".rest", ".fit", ".lol", ".cam", ".quest",
             ".zip", ".mov", ".monster", ".click", ".link", ".work", ".gdn",
             ".bid", ".win", ".stream", ".trade", ".review", ".date", ".faith",
             ".cricket", ".science", ".party", ".accountant", ".loan", ".download"]
PHISH_PATH_KWS = ["login", "signin", "sign-in", "verify", "verification", "secure",
                  "account", "update", "confirm", "banking", "paypal", "wallet",
                  "credential", "password", "ebayisapi", "webscr", "wp-admin"]

def feats(url):
    f = {}
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
        path = (p.path or "").lower()
        f["host"] = host
        f["shortener"] = any(s in host for s in SHORTENERS)
        f["susp_tld"] = any(host.endswith(t) for t in SUSP_TLDS)
        f["punycode"] = "xn--" in host
        after = url.split("://", 1)[1] if "://" in url else url
        f["dblslash"] = "//" in after
        f["port"] = p.port is not None and p.port not in (80, 443)
        f["digit_host"] = sum(c.isdigit() for c in host) >= 4
        f["path_kw"] = any(k in path for k in PHISH_PATH_KWS)
        f["long_host"] = len(host) > 30
    except Exception:
        pass
    return f

miss_fn, miss_fp = [], []
for r in A:
    pred, _ = java_port(r["URL"])
    truth = "PHISH" if r["Label"] == "-1" else "LEGIT"
    if pred == "SAFE" and truth == "PHISH":
        miss_fn.append(r["URL"])
    elif pred == "PHISHING" and truth == "LEGIT":
        miss_fp.append(r["URL"])

print(f"FN={len(miss_fn)} FP={len(miss_fp)}")
for feat in ["shortener", "susp_tld", "punycode", "dblslash", "port",
             "digit_host", "path_kw", "long_host"]:
    fn_hit = sum(1 for u in miss_fn if feats(u).get(feat))
    fp_hit = sum(1 for u in miss_fp if feats(u).get(feat))
    print(f"{feat:12s} FN_hit={fn_hit:4d}/{len(miss_fn)}  FP_hit={fp_hit:3d}/{len(miss_fp)}")
