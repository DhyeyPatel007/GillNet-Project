# GillNet AI — Multi-Layer Cybersecurity Platform

GillNet AI is an advanced AI-powered cybersecurity suite engineered to detect phishing websites, identify fraudulent/scam messages and screenshots, analyze password vulnerabilities, and protect digital identities in real time.

---

## 🌟 Architecture Overview

The repository is structured as a multi-tier platform:

```
Gillnet-Project/
├── GillNet-AI-main/          # Modern React Frontend (TanStack Start, SSR, Tailwind CSS, Lucide icons)
├── GillNet-AI-Backend/       # Java Spring Boot 3 Backend Service (JWT Auth, Google OAuth, REST APIs)
│   └── ml-service/           # Python ML Inference Microservice (Random Forest URL detector, Phishing heuristic engine)
├── GillNet-AI-dashboard/     # Supplementary dashboard assets & legacy reference
├── GillNet_AI_Audit_Report   # Comprehensive security & system audit documentation (HTML & PDF)
└── README.md
```

---

## 🚀 Key Features

1. **AI Phishing Link Scanner**:
   - Analyzes URL structural lexical features, domain entropy, subdomains, IP host patterns, and SSL attributes using a retrained Random Forest ML model.
2. **Screenshot & Message Phishing Detection**:
   - Multi-layer analysis for phishing emails, fake wire transfer alerts, banking scams, and lottery fraud.
3. **Password Security Analysis**:
   - Password strength evaluation, Shannon entropy calculation, character composition rules, and breach exposure warnings.
4. **Authentication Suite**:
   - **Google OAuth**: One-click Google Sign-In with JWT session issuance.
   - **Email & Password**: BCrypt hashing with persistent disk-backed store and password reset flow.
5. **Interactive Dashboard**:
   - Dark / Light mode toggle, live scan counters, risk level visualizations, threat categorization, and recent scan logs.

---

## 🛠️ Quick Start (Running Locally)

### 1. Python ML Service
```bash
cd GillNet-AI-Backend/ml-service
python -m venv .venv
.venv\Scripts\activate      # Windows
pip install -r requirements.txt
python app.py               # Runs on port 5000
```

### 2. Spring Boot Backend
```bash
cd GillNet-AI-Backend
./mvnw clean spring-boot:run   # Runs on port 8081
```

### 3. React Frontend
```bash
cd GillNet-AI-main
bun install                 # or npm install
bun run dev                 # Runs on http://localhost:8080
```

---

## 🔒 Security & Privacy
- Zero plaintext password persistence (all stored using salted BCrypt).
- JWT token signing with configurable expiration and secrets.
- Input validation to distinguish URLs from paragraphs/free text.
- CORS policy configured for secure frontend-backend communication.
