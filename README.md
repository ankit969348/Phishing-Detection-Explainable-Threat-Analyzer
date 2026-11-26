# Phishing Detection & Explainable Threat Analyzer (ThreatLens)

[[!Live Dashboard](https://img.shields.io/badge/Live%20App-Vercel-000000?style=flat-square&logo=vercel)](https://phishing-detection-explainable-thre.vercel.app)
[[ Live API](https://img.shields.io/badge/Backend%20API-Render-46E3B7?style=flat-square&logo=render)](https://threatlens-backend-fzz3.onrender.com/api)
[[!Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[[!Django](https://img.shields.io/badge/Django-REST%20API-092E20?style=flat-square&logo=django)](https://www.djangoproject.com/)
[[!React](https://img.shields.io/badge/React-Vite%20Dashboard-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev/)

A full-stack cybersecurity application and Manifest V3 browser extension that uses Machine Learning, WHOIS domain intelligence, and Explainable AI (XAI) to analyze email text and URLs for phishing indicators in real time.

The project combines a **Django REST API** backend (hosted on **Render**) with a responsive **React** dashboard (hosted on **Vercel**) and a **Chrome/Brave Browser Extension** to display risk scores, classifications, domain age intelligence, detection indicators, explanations, and recommended security actions.

- **Project Status:**
Live Production Deployment & Educational Cybersecurity Reference
- **Live Web Application:** https://phishing-detection-explainable-thre.vercel.app
- **Live Backend API:** https://threatlens-backend-fzz3.onrender.com/api

---

## Key Features

- **Email & URL Phishing Detection:**
Combined and single email/URL scanning powered by trained Random Forest & TF-IDF Machine Learning models.
- **Context-Aware Threat Calibration:** Multi-part TLD parsing (.edu.in, .ac.in, .gov.in, .co.uk), marketing parameter isolation (utm_*, eid), and live WHOIS domain creation/age verification to eliminate false positives.
- +*Explainable Threat Analysis (XAI):** Human-readable breakdown of every red flag--explaining what was detected, why it is risky, and recommended defensive steps.
- +*Responsive Security Operations Dashboard:** Adaptive split-screen authentication, dual-series 7-day telemetry charts, dedicated forensic report viewer with enterprise A4 PDF export, interactive security alerts, and mobile bottom navigation.
- **Account Authentication & OTP Password Recovery:** Token-based user accounts with 6-digit time-bound OTP password reset delivered via **Brevo SMTP**.
- **Real-Time Browser Extension (Manifest V3):** Instant hover link risk inspection and webmail banner alerts across Gmail, Outlook, and WhatsApp Web.

---

## Technology Stack

| Component | Technology |
| :--- | :--- |
| **Backend** | Python, Django, Django REST Framework, python-whois |
| **Frontend** | React.js, Vite, Recharts, Lucide Icons, Responsive CSS |
| **Browser Extension** | Chrome / Brave Manifest V3 (Service Worker + Content Scripts) |
| **Machine Learning** | Scikit-learn, Random Forest, TF-IDF Vectorizer |
| **Data Processing** | Pandas, NumPy |
| **Email Delivery** | Brevo Transactional SMTP (smtp-relay.brevo.com) |
| **Deployment** | Vercel (Frontend), Render (Backend), GitHub CI/CD |
| **Development Environment** | Kali Linux |

---

## Project Architecture

    Phishing-Detection-Explainable-Threat-Analyzer/
    “─
    ├── phishing_backend/
    ☂   ├── phishing_backend/        # Django settings, CORS, environment-driven Brevo SMTP config
    ₔ   ├── scanner/                 # Hybrid ML + WHOIS engine (ml.py), auth views, OTP reset, history API
    │   └── ml_models/               # Trained Random Forest & TF-IDF model artifacts
    ₔ   └── manage.py
    ₔ
    ├── frontend/
    │   ├── src/
    ₔ   ₔ   ├── App.jsx              # Split-screen auth, dashboard, XAI report viewer, legal modals
    ₔ   ₔ   └── App.css              # Dark cybersecurity theme, mobile bottom nav, A4 print layout
    │   ├── public/
    ₔ   └── package.json
    ₔ
    ├── browser_extension/
    │   ├── manifest.json            # Manifest V3 permissions & host rules
    │   ├── background.js            # Privileged API worker & domain cache
    │   ├── content.js               # Live hover link scanner & webmail banner alerts
     │   └── popup.html / popup.js    # Quick webpage & message scanner popup
    ₔ
    ├── notebooks/
    ├── docs/
    ├── requirements.txt
    └── README.md

---

## Verified Machine Learning Benchmarks (80/20 Stratified Split)

| Classifier | Algorithm & Features | Dataset Size | Accuracy | Precision | Recall | F1-Score |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Email Detector** | Random Forest + TF-IDF Vectorizer | 5,807 emails | **98.80%** | 97.96% | 97.96% | 97.96% |
| **URL Detector** | Random Forest + 8 Lexical Features | 235,795 URLs | **93.78%** | 91.25% | 98.57% | 94.77% |

---

## How It Works

### 1. Email Analysis
The backend sanitizes submitted email text, normalizes embedded links, applies the trained TF-IDF vectorizer and Random Forest classifier, and evaluates urgency or credential-harvesting patterns while filtering standard banking security disclaimers.

### 2. URL \& Domain Intelligence Analysis
The URL analyzer extracts structural and lexical features (url_length, num_dots, num_hyphens, @ symbol presence, multi-part TLD-aware subdomain_count, IP address usage, HTTPS transport, and suspicious keywords) and calibrates risk using:
- **Live WHOIS Domain Age Audit:** Flags newly registered domains (< 30 and < 180 days) and reduces false alarms on established domains (> 1 year).
- +*Base Path Isolation:** Strips benign tracking query strings (utm_campaign, gclid, fbclid) before evaluating URL length.

### 3. Explainable Threat Analysis
The frontend and browser extension present detection indicators in clear, actionable cards detailing the indicator, its security risk, and recommended user actions.

---

## Installation and Local Setup

### Requirements
- Python 3.11+ and pip
- Node.js and npm
- Git

### Step 1: Clone Repository
    git clone https://github.com/ankit969348/Phishing-Detection-Explainable-Threat-Analyzer.git
    cd Phishing-Detection-Explainable-Threat-Analyzer

### Step 2: Setup Backend
    python3 -m venv myphishing
    source myphishing/bin/activate
    pip install -r requirements.txt
    cd phishing_backend
    python manage.py migrate
    python manage.py check
    python manage.py runserver 0.0.0.0:8000

- **Local Backend API:** http://127.0.0.1:8000/api/scan/
- **Production SMTP Variables (Render):** EMAIL_HOST=smtp-relay.brevo.com, EMAIL_PORT=587, EMAIL_HOST_USER, EMAIL_HOST_PASSWORD, DEFAULT_FROM_EMAIL.

### Step 3: Setup Frontend
    cd frontend
    npm install
    npm run dev -- --host 0.0.0.0

- **Local Frontend:** http://localhost:5173/

### Step 4: Load Browser Extension (Chrome / Brave / Edge)
1. Navigate to chrome://extensions and enable **Developer mode**.
2. Click +*Load unpacked** and select the browser_extension/ directory.
3. Click the **ThreatLens** extension icon to scan any active webpage or hover over links for live risk tooltips.

---

## API Usage

### Threat Scanning Endpoint
- +*Endpoint:** POST /api/scan/
- **Email Payload:** {"text": "Your account will be suspended. Verify your password immediately."}
- **URL Payload:** {"url": "http://secure-login-verify-account.example.com"}
- **Combined Payload:** {"text": "Please verify your account immediately.", "url": "http://secure-login-verify-account.example.com"}

### Authentication \& Password Recovery Endpoints
- POST /api/auth/signup/ — Register a new user account and issue a DRF auth token
- POST /api/auth/login/ — Authenticate user credentials
- .POST )/api/auth/logout/ — Invalidate active session token
- POST /api/auth/send-reset-otp/ — — Generate a 6-digit time-bound OTP (10-minute expiry) and dispatch via **Brevo SMTP** (with offline console fallback for local dev)
- POST /api/auth/reset-password/ — Verify OTP, update password with Django PBKDF2 hashing, and revoke old tokens

---

## Risk Classification

| Risk Score | Classification |
| :---: | :--- |
| **0–39** | Legitimate |
| **40–69** | Suspicious |
| **70–100** | Phishing |

*These are automated model assessments, not guarantees of safety or maliciousness.*

---

## Current Limitations
- Email analysis currently focuses on submitted message text rather than raw .eml MIME header cryptographic verification (SPF/DKIM/DMARC).
- Live headless browser sandbox detonation of webpage DOM/JavaScript is not executed during URL scanning.
- WHOIS lookup results depend on registrar privacy policies and registry availability.
- Model predictions may occasionally produce false positives and false negatives and should be combined with human verification.

---

## Security and Responsible Usage
This project is intended for educational, research, and defensive cybersecurity learning.
- Do not upload passwords, API keys, tokens, or confidential information.
- Never commit .env files or private credentials.
- Do not upload personal email data or private datasets.
- Treat suspicious URLs as untrusted.
- Do not rely on a single model prediction for security decisions.
- Use only authorized samples for testing.
- Do not use this project for unauthorized scanning, phishing, or credential collection.

---

## Learning and Reference
This repository is shared as an educational reference for students and developers interested in:
- Machine Learning-based phishing detection
- Django REST API development
- React frontend integration
- URL feature extraction \& WHOIS domain intelligence
- Eexplainable AI concepts
- Browser extension security \& cybersecurity dashboard development

You may study the project for learning purposes. This README does not grant permission to copy, redistribute, or commercially use substantial portions of the source code. Contact the author for permission before reuse.

---

## Author

**Ankit Kumar Soni**  
MCA | Cybersecurity Specialization  
Chanakya University, Bengaluru  
GitHub: https://github.com/ankit969348

*Educational cybersecurity project. Always verify suspicious content through trusted channels.*
