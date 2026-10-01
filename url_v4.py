#!/usr/bin/env python3
"""v4 URL heuristic: more signals, trusted-infra whitelist, tuned weights."""
import csv, random, re, json
from urllib.parse import urlparse

random.seed(1234)
rows = list(csv.DictReader(open(
    "/home/hatch/workspace/gillnet-project/GillNet-AI-Backend/ml-service/phishing_20k_real.csv")))
random.shuffle(rows)
A, B = rows[:10000], rows[10000:]

SHORTENERS = ["bit.ly", "tinyurl.com", "tinyurl", "t.co", "goo.gl", "ow.ly",
              "is.gd", "buff.ly", "adf.ly", "j.mp", "cutt.ly", "shorte.st",
              "tiny.cc", "rb.gy", "shorturl.at", "lnkd.in", "fb.me", "t.ly",
              "bitly.com", "s.id", "short.gy"]
SUSP_TLDS = [".tk", ".xyz", ".top", ".club", ".online", ".site", ".buzz", ".cf",
             ".gq", ".ml", ".pw", ".rest", ".fit", ".lol", ".cam", ".quest",
             ".zip", ".mov", ".monster", ".click", ".link", ".work", ".gdn",
             ".bid", ".win", ".stream", ".trade", ".review", ".date", ".faith",
             ".cricket", ".science", ".party", ".loan", ".download"]
PATH_KWS = ["login", "signin", "sign-in", "verify", "verification", "secure",
            "account", "update", "confirm", "banking", "wallet", "credential",
            "password", "ebayisapi", "webscr", "authenticate", "oauth"]
HOST_KWS = ["login", "verify", "banking", "update", "paypal", "account",
            "wallet", "signin", "confirm"]
BRANDS = ["paypal", "apple", "amazon", "microsoft", "netflix", "chase",
          "wellsfargo", "bankofamerica", "linkedin", "facebook", "instagram",
          "gmail", "outlook", "office365", "ebay", "hsbc", "citibank",
          "santander", "binance", "coinbase", "metamask", "dhl", "fedex",
          "google", "alibaba", "whatsapp", "telegram", "absa", "simplii",
          "standardbank", "fnb", "nedbank", "icici", "hdfc", "sbi"]
FREEDNS = ["duckdns.org", "no-ip.", "dyndns", "github.io", "glitch.me",
           "netlify.app", "pages.dev", "web.app", "firebaseapp.com",
           "blogspot.", "wordpress.com", "weebly.com", "wixsite.com",
           "000webhost", "altervista.org", "yolasite.com"]
B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


def domain_match(host, dom):
    return host == dom or host.endswith("." + dom)


def features(url):
    f = {}
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
        if not p.hostname:
            raise ValueError
        pathq = ((p.path or "") + "?" + (p.query or "")).lower()
        f["ip"] = bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host))
        f["long"] = len(url) > 75
        f["at"] = "@" in url
        f["hyphen"] = "-" in host
        f["dots"] = host.count(".") > 2
        f["http"] = not url.lower().startswith("https://")
        f["host_kw"] = any(k in host for k in HOST_KWS)
        f["shortener"] = any(domain_match(host, s) for s in SHORTENERS)
        f["susp_tld"] = any(host.endswith(t) for t in SUSP_TLDS)
        f["puny"] = "xn--" in host
        after = url.split("://", 1)[1] if "://" in url else url
        f["dblslash"] = "//" in after
        try:
            f["port"] = p.port is not None and p.port not in (80, 443)
        except ValueError:
            f["port"] = True
        f["digits"] = sum(c.isdigit() for c in host) >= 3
        f["path_kw"] = any(k in pathq for k in PATH_KWS)
        f["long_host"] = len(host) > 30
        f["brand_path"] = any(b in pathq and not domain_match(host, b)
                              and (b + ".com") not in host and (b + ".") not in host
                              for b in BRANDS)
        f["freedns"] = any(domain_match(host, d) if d.startswith(".") or "." in d
                           else d in host for d in FREEDNS)
        f["b64path"] = bool(B64.search(p.path or ""))
        h = host
        trusted = (h.endswith(".gov") or ".gov." in h or h.endswith(".edu")
                   or ".edu." in h or ".ac." in h or h.endswith(".arpa")
                   or "awsdns-" in h)
        f["trusted"] = trusted
        f["parse_fail"] = False
    except Exception:
        f = {"parse_fail": True, "trusted": False}
    return f


def v4(url, W, thr):
    f = features(url)
    if f.get("parse_fail"):
        return ("PHISHING", 80)
    s = 15
    for k in ("ip", "long", "at", "dots", "http", "host_kw", "shortener",
              "susp_tld", "puny", "dblslash", "port", "digits", "path_kw",
              "long_host", "brand_path", "freedns", "b64path"):
        if f.get(k):
            s += W[k]
    if f["hyphen"] and not f["trusted"]:
        s += W["hyphen"]
    if f["trusted"]:
        s = min(s, 10)
    s = min(100, max(0, s))
    return ("PHISHING" if s >= thr else "SAFE", s)


def acc(fn, split):
    ok = sum(1 for r in split
             if (fn(r["URL"])[0] == "PHISHING") == (r["Label"] == "-1"))
    return ok / len(split)


W = dict(ip=40, long=15, at=25, hyphen=15, dots=20, http=15, host_kw=20,
         shortener=25, susp_tld=20, puny=30, dblslash=25, port=20,
         digits=25, path_kw=20, long_host=15, brand_path=25, freedns=15,
         b64path=15)
best = (0, None)
for thr in (45, 50, 55):
    a = acc(lambda u: v4(u, W, thr), A)
    print(f"thr={thr} tune_acc={a:.4f}", flush=True)
    if a > best[0]:
        best = (a, thr)
print("best:", best, flush=True)
json.dump({"W": W, "thr": best[1]},
          open("/home/hatch/workspace/gillnet-project/url_v4_params.json", "w"))
for name, split in (("TUNE", A), ("HELDOUT", B)):
    a = acc(lambda u: v4(u, W, best[1]), split)
    print(f"v4 {name}: acc={a:.4f}", flush=True)
