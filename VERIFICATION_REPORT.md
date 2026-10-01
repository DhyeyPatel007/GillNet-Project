# GillNet Verification Report
**Date:** 2026-10-01 ~10:00 IST
**Repo:** https://github.com/DhyeyPatel007/GillNet-Project.git
**Deployed commit:** `c2c8c84` (pushed to `main`; Render auto-deployed)

## What changed in this pass

1. **URL scanner retuned (v4 weights)** in `UrlScanService.java` — suspicious-TLD list, shortener domains, brand-impersonation, free-hosting, base64-path signals.
2. **Text scanner rebuilt** in `PhishingScanService.java` — expanded lure/urgency/credential-harvest/premium-rate/shortcode signals + an embedded 1,632-word Naive Bayes spam model used as a tiebreaker (score ≥ 25 escalates weak-signal messages).
3. **Screenshot tab repaired** — the backend now accepts the frontend OCR `extractedText` and classifies it with the text engine. The filename is context only. With no OCR text the service returns an explicit low-confidence coverage-gap verdict instead of inventing pixel/visual-inspection claims.
4. **Chat UI added** — floating `ChatAssistant` widget mounted on the dashboard, wired to `/api/chat`.
5. **10 new unit tests** for scanner behavior. Backend suite: **25/25 pass.**

## Measured accuracy (Java engine, labeled held-out data — not curated samples)

| Engine | Dataset | Accuracy | Precision | Recall |
|---|---|---|---|---|
| URL v4 | 20,000 labeled URLs (`phishing_20k_real.csv`; label −1 = phishing) | **98.97%** | 98.82% | 99.11% |
| Text hybrid | 2,574 held-out SMS (UCI SMS Spam Collection, split seed 42; tune/held-out separated before threshold selection) | **97.67%** | 99.67% | 83.66% |

The text threshold (NB ≥ 25) was chosen on the 3,000-message tune split (98.50%, zero false positives there) and measured on the untouched held-out split. A lower threshold (NB ≥ 18) reached 99.1% on tune but only 98.0% on held-out with 5 false positives, so it was rejected — precision matters more than squeezing the headline number.

## Live production tests — 2026-10-01 ~10:00 IST (`gillnet-backend-recovery.onrender.com`, deployed build)

| Check | Result |
|---|---|
| Text tab `/api/phishing/analyze-text` (same 20-case set the dashboard uses) | **19/20 (95.0%)** — was 75% before this pass. One miss: legit subscription-renewal notice flagged SUSPICIOUS. |
| URL `/api/url/analyze` (5 probes: 2 phishing, 3 legit) | **5/5 correct** |
| Screenshot `/api/phishing/analyze-image` (4 behavioral cases) | **4/4 correct**: OCR phishing text → PHISHING (verdict follows text, not filename); OCR benign text + sensitive filename → SAFE; no OCR + sensitive filename → SUSPICIOUS with explicit "No on-screen text" coverage gap; no OCR + benign filename → SAFE low-confidence. No false visual-inspection claims anywhere. |
| Password `/api/password/analyze` | Sensible: `Tr0ub4dor&3xY9!qW` → VERY_STRONG 100; `password123` → WEAK 10; `correct horse battery staple` → GOOD 55 |
| Chat `/api/chat` | Correct OTP-scam advice; 1 credit deducted (73 → 72) |
| Credits | Register → 100; scans deduct exactly 1; failed scans don't charge (verified in prior pass) |

## Honest gaps against the 99% target

- **URL: 98.97%** — within measurement noise of 99%, but strictly under it.
- **Text: 97.67%** — short of 99%. Reaching 99% on real-world SMS spam needs a properly trained ML model, not a heuristic+NB hybrid; that is a bigger project than this pass.
- **Screenshot without OCR text** is low-confidence filename triage by design — it cannot be 99% and doesn't claim to be.

## Still open (needs your hands)

1. **Atlas cleanup:** delete test users `retest-1790824786@gillnet.test`, `accuracy-*`, `accuracy2-*`, `msgdbg-*`, `livetest-*`, `tok2-*` at `@gillnet.test` via Atlas Data Explorer (VM DNS can't reach Atlas directly).
2. **Rotate secrets:** Atlas DB password and `JWT_SECRET` in the Render dashboard (old values appeared in task history). Then redeploy + retest.
3. **Google login:** add both frontend origins in Google Cloud console, then do one real tap-to-login on the live site.
4. Revoke the old GitHub PAT from 2026-09-30; `gh auth logout` was for the VM session.

## Live browser accuracy test — 2026-10-01 ~10:15 IST
- Ran 60 cases against production (Vercel frontend UI for URL + Text; screenshot endpoint via API with OCR-equivalent text, since the browser automation could not target the hidden file input).
- URL scanner (real UI): **20/20** — 10/10 phishing (incl. IP-hosted bank lures) PHISHING, 10/10 legit SAFE.
- Text tab (real UI): **19/20** — 9/10 spam caught (mix of PHISHING/SUSPICIOUS), 10/10 ham SAFE. One miss: "XXXMobileMovieClub" premium-rate lure scored SAFE (10/100).
- Screenshot tab (same /api/phishing/analyze-image endpoint the UI calls, extractedText as the frontend's Tesseract would produce): **20/20** — 10/10 phishing-text images PHISHING (risk 47–100), 10/10 benign-text images SAFE (risk 0–10).
- Combined: **59/60 = 98.3%**.
- Finding: the Screenshot tab's "click to browse" drop zone did not open a file chooser on click in automation — possible frontend UX issue worth a manual click-test.
