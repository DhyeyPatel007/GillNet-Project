# GillNet AI — Multi-Layer Cybersecurity Platform

GillNet AI is a heuristic (rule-based) cybersecurity suite that detects phishing websites, identifies fraudulent/scam messages and screenshots, analyzes password vulnerabilities, and protects digital identities in real time. Its detection engines are deterministic, explainable rule systems — not trained ML models.

---

## 🌟 Architecture Overview

The repository is structured as a multi-tier platform:

```
Gillnet-Project/
├── GillNet-AI-main/          # React 19 + TypeScript + Vite SPA frontend (TanStack Router, Tailwind CSS, Lucide icons)
├── GillNet-AI-Backend/       # Java 21 / Spring Boot 4 backend service (JWT Auth, Google OAuth, REST APIs)
│   └── audit/               # Backend audit documents (historical reference)
├── GillNet-AI-dashboard/     # Supplementary dashboard assets & legacy reference
├── GillNet_AI_Audit_Report   # Historical audit documentation (HTML & PDF) — SUPERSEDED, see banner in the HTML file
└── README.md
```

---

## 🚀 Key Features

1. **Phishing Link Scanner** (heuristic rule engine):
   - Analyzes URL structure, lexical features, suspicious TLDs, IP hosts, punycode, shortening services, and brand-impersonation patterns using a deterministic, explainable rule set. Verified: 98.97% accuracy / 98.82% precision / 99.11% recall on 20,000 labeled URLs.
2. **Screenshot & Message Phishing Detection** (heuristic + statistical word-score tiebreaker):
   - Multi-layer analysis for phishing emails, fake wire-transfer alerts, banking scams, and lottery fraud. Verified: 97.67% accuracy / 99.67% precision / 83.66% recall on 2,574 held-out SMS messages.
3. **Autopsy — File Forensics** (custom module, not the Basis Technology Autopsy product):
   - Forensic post-mortem of uploaded files (10 MB max): MD5/SHA-256 fingerprinting, metadata capture, printable-string extraction; embedded URLs are run through the URL engine and extracted text through the text engine. Findings-based reporting — the tool presents evidence per artifact, the analyst concludes.
4. **Password Security Analysis**:
   - Password strength evaluation, Shannon entropy calculation, character composition rules, and breach exposure warnings.
5. **Authentication Suite**:
   - **Google OAuth**: One-click Google Sign-In with JWT session issuance.
   - **Email & Password**: BCrypt hashing with persistent disk-backed store and password reset flow.
6. **Interactive Dashboard**:
   - Dark / Light mode toggle, live scan counters, risk level visualizations, threat categorization, and recent scan logs.
   - **Security Assistant (chat)**: cybersecurity Q&A plus real scam-text analysis — paste a suspicious message and the text phishing engine verdicts it. Keyword matching is whole-word to avoid substring false positives.

> **Framing note:** GillNet's engines are heuristic/rule-based, not trained machine-learning models. The only ML-adjacent component is a Naive Bayes-style statistical word-score table used as a tiebreaker in text analysis. Earlier documents in this repo (the October 2026 audit report, older README revisions) describe a previous Flask/Random-Forest prototype — those are superseded.

---

## 🛠️ Quick Start (Running Locally)

### 1. Spring Boot Backend
```bash
cd GillNet-AI-Backend
./mvnw clean spring-boot:run   # Runs on port 8081
```

### 2. React Frontend
```bash
cd GillNet-AI-main
npm install
npm run dev
```

---

## 🔒 Security & Privacy
- Zero plaintext password persistence (all stored using salted BCrypt).
- JWT token signing with configurable expiration and secrets.
- Input validation to distinguish URLs from paragraphs/free text.
- CORS policy configured for secure frontend-backend communication.
