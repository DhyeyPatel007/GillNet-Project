# GillNet AI — Project Context

## 1. Project Overview

GillNet AI is an AI-assisted personal cybersecurity web application designed to help normal users identify common online security threats.

The system focuses on making cybersecurity simple and understandable instead of only displaying technical information.

The main capabilities of GillNet AI will be:

1. Phishing URL Detection
2. Scam / Suspicious Message Analysis
3. Password Strength Analysis
4. AI-based Cybersecurity Assistant
5. Security Recommendations
6. Scan History and Dashboard

This project is being developed as a university Project Exhibition project by a team of 5 students.

The development time is approximately 1–1.5 months, so the project should remain practical and achievable for beginner/intermediate developers.

---

# 2. Main Goal

A user should be able to give GillNet AI suspicious digital content such as:

- A website URL
- A suspicious/scam message
- A password for strength analysis
- A cybersecurity-related question

GillNet AI should analyze the input and provide an understandable security result.

Example:

User enters:

http://suspicious-example-login.com

GillNet AI could return:

Risk Level: HIGH

Classification:
Potential Phishing Website

Reasons:
- Suspicious URL structure
- Unusual domain characteristics
- Phishing-related patterns detected

Recommendation:
Do not enter passwords, OTPs, banking information, or personal details on this website.

---

# 3. Planned Technology Stack

## Frontend

React

Responsibilities:

- Landing page
- Login/Register pages
- Dashboard
- URL scanner interface
- Scam message analyzer interface
- Password analyzer interface
- AI assistant interface
- Scan history
- Displaying security results

The UI will first be designed in Figma and then implemented in React.

---

## Backend

Java + Spring Boot

The Spring Boot backend will act as the central controller of GillNet  AI.

Responsibilities:

- REST APIs
- Receive requests from frontend
- Validate user input
- Communicate with database
- Communicate with AI/ML services
- Apply application logic
- Return results to frontend
- Manage scan history
- Later handle authentication if time permits

Possible API structure:

GET /api/test

POST /api/url/analyze

POST /api/message/analyze

POST /api/password/analyze

POST /api/chat

GET /api/history

---

# 4. Phishing URL Detection

GillNet  AI will NOT train a large machine-learning model from scratch.

Because the team has limited development time and ML experience, we will use an existing/pretrained phishing detection model or build from an established dataset/model approach.

The phishing detection component may run as a small Python ML service.

Possible architecture:

React Frontend
      |
      v
Spring Boot Backend
      |
      v
Python ML Service
      |
      v
Phishing Model
      |
      v
Prediction
      |
      v
Spring Boot
      |
      v
React

The frontend should NOT communicate directly with the ML model.

Spring Boot remains the main backend.

Possible prediction:

SAFE
SUSPICIOUS
PHISHING

The application may also provide a risk score and explanation.

---

# 5. Scam Message Analyzer

Users can paste suspicious messages such as:

"Your bank account has been blocked. Verify immediately using this link."

GillNet AI analyzes the message for signs such as:

- Urgency
- Suspicious links
- Requests for OTP/password
- Financial scams
- Fake rewards
- Impersonation
- Threatening language
- Requests for sensitive information

The system should return:

- Risk classification
- Risk explanation
- Suspicious indicators
- Recommended action

AI APIs may assist with natural-language explanation.

AI output must be treated as advisory and not guaranteed to be correct.

---

# 6. Password Strength Analyzer

Users can enter a password to evaluate its strength.

IMPORTANT:

Passwords should NOT be permanently stored in the database.

The analyzer can check:

- Password length
- Uppercase characters
- Lowercase characters
- Numbers
- Special characters
- Repeated patterns
- Common password patterns

Possible result:

Strength: WEAK / MEDIUM / STRONG

The application should explain how the password can be improved.

Most password checks should be rule-based instead of unnecessarily using AI.

---

# 7. AI Cybersecurity Assistant

GillNet  AI will contain a simple cybersecurity assistant.

Users can ask questions such as:

"What should I do if I clicked a phishing link?"

"How can I recognize an OTP scam?"

"Is it safe to share my CVV?"

The assistant should provide simple cybersecurity guidance.

An external LLM API may be used depending on free-tier availability.

The assistant must focus on defensive cybersecurity and user safety.

---

# 8. Database

A database will be used for application data.

Preferred option:

MongoDB / MongoDB Atlas

Possible stored information:

Users

- id
- name
- email
- passwordHash (only if authentication is implemented)

Scan History

- scanId
- userId
- scanType
- sanitizedInput/reference
- result
- riskLevel
- timestamp

The application must NOT store plaintext passwords submitted to the Password Analyzer.

---

# 9. Dashboard

After login/getting started, the user enters the GillNet  dashboard.

Possible sidebar:

Dashboard

URL Scanner

Scam Detector

Password Analyzer

AI Assistant

History

The dashboard can display:

- Total scans
- Safe results
- Suspicious results
- High-risk results
- Recent scans

---

# 10. Landing Page

The public landing page will follow the existing Figma design.

Main headline:

Stay Secure.
Stay Ahead.

The landing page should contain:

- Navbar
- Hero section
- GillNet AI introduction
- Features
- How It Works
- Security tools
- About
- Final CTA
- Footer

The landing page should visually feel like a real cybersecurity SaaS product rather than a typical college project.

---

# 11. Basic System Architecture

User
 |
 v
React Frontend
 |
 | HTTP / JSON
 v
Java Spring Boot Backend
 |
 |-----------------------------|
 |              |              |
 v              v              v
Database    ML Service      AI API
MongoDB      Python          LLM
               |
               v
        Phishing Model

Spring Boot acts as the central backend and integration layer.

---

# 12. Proposed Repository Structure

GillNet -AI

├── frontend/
│   └── React application
│
├── backend/
│   └── Java Spring Boot application
│
├── ml-service/
│   └── Python phishing detection service
│
├── docs/
│   └── Project documentation
│
├── PROJECT_CONTEXT.md
│
└── README.md

---

# 13. Team Structure

The project has 5 members.

Work is divided approximately into:

Member 1:
Backend + Integration

Main technologies:
Java
Spring Boot
REST APIs
Git/GitHub

Member 2:
Frontend + UI

Main technologies:
Figma
React
HTML
CSS
JavaScript

Member 3:
AI / ML

Main technologies:
Python
Phishing detection model
Model integration
Basic ML concepts

Member 4:
Database + Authentication

Main technologies:
MongoDB
MongoDB Atlas
Database design
Basic authentication concepts

Member 5:
Testing + Documentation + Integration Support

Main technologies:
Postman
API testing
Git/GitHub
Documentation
Presentation/demo preparation

Members may help each other when required.

---

# 14. Development Strategy

The project should be developed incrementally.

Phase 1:
Project setup and GitHub repository

Phase 2:
UI design and basic frontend

Phase 3:
Spring Boot backend and basic REST APIs

Phase 4:
Connect React frontend with Spring Boot

Phase 5:
Implement individual cybersecurity modules

Phase 6:
Database integration

Phase 7:
ML phishing model integration

Phase 8:
AI assistant integration

Phase 9:
Testing, bug fixing and UI improvements

Phase 10:
Deployment, documentation and exhibition preparation

Do NOT attempt all technologies simultaneously.

Each component should work independently before integration.

---

# 15. Important Development Rules

1. Keep the architecture beginner-friendly.

2. Prefer working features over unnecessary complexity.

3. Spring Boot is the primary backend.

4. React should communicate with Spring Boot through REST APIs.

5. The ML model should not communicate directly with the frontend.

6. Never store passwords entered into the password analyzer.

7. API keys and secrets must never be committed to GitHub.

8. Secrets should be stored using environment variables or ignored configuration files.

9. Test APIs independently before connecting them to the frontend.

10. Use Git branches for team development rather than everyone directly editing main.

11. Commit frequently with meaningful commit messages.

12. AI tools may generate code, but team members should understand the important code they use.

13. Avoid adding features simply because an AI tool suggested them.

14. The final project must be explainable by the team during evaluation.

---

# 16. Scope Priority

## Must Have

- Landing page
- Dashboard
- Phishing URL detection
- Scam message analyzer
- Password strength analyzer
- Java Spring Boot backend
- Functional frontend-backend communication

## Should Have

- Database
- Scan history
- AI-generated security explanations
- Cybersecurity assistant

## Optional If Time Permits

- Full user authentication
- Analytics/charts
- PDF security report
- Dark/light mode
- Additional security tools
- Deployment improvements

The Must Have features should always be completed before optional features.

---

# 17. Instructions for AI Coding Assistants

When helping GillNet AI 

1. Read this PROJECT_CONTEXT.md first.

2. Do not redesign the entire architecture unless explicitly requested.

3. Assume the developers are students with limited full-stack project experience.

4. Explain important code rather than only generating it.

5. Prefer simple, maintainable implementations.

6. Do not introduce unnecessary frameworks or dependencies.

7. Keep Spring Boot as the main backend.

8. Generate code compatible with the existing repository structure.

9. When changing existing code, explain which files need modification.

10. Do not expose API keys, database credentials, or secrets.

11. Prioritize completing a working MVP within the available development time.

12. If a proposed feature significantly increases complexity, explain the trade-off before implementing it.