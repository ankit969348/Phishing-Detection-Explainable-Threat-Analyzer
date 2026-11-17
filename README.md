
# Phishing Detection & Explainable Threat Analyzer

An educational cybersecurity project that uses Machine Learning to analyze email text and URLs for potential phishing indicators.

The project combines a Django REST API backend with a React dashboard to display risk scores, classifications, detection indicators, explanations, and recommended security actions.

**Project Status:** Local development and educational reference project.

## Key Features

- Email phishing detection
- URL phishing detection
- Combined email and URL scanning
- Machine Learning-based classification
- Risk score visualization
- Explainable Threat Analysis
- Detection indicators and security recommendations
- Scan history and dashboard
- Django REST API integration with React

## Technology Stack

| Component | Technology |
|---|---|
| Backend | Python, Django, Django REST Framework |
| Frontend | React.js, Vite, JavaScript |
| Machine Learning | Scikit-learn, Random Forest, TF-IDF |
| Data Processing | Pandas, NumPy |
| Environment | Kali Linux |
| Version Control | Git, GitHub |

## Project Architecture

```text
Phishing-Detection-Explainable-Threat-Analyzer/
│
├── phishing_backend/
│   ├── phishing_backend/
│   ├── scanner/
│   └── ml_models/
│
├── frontend/
│   ├── src/
│   ├── public/
│   └── package.json
│
├── notebooks/
├── docs/
├── requirements.txt
└── README.md
```

## Verified Machine Learning Benchmarks (80/20 Stratified Split)

| Classifier | Algorithm & Features | Dataset Size | Accuracy | Precision | Recall | F1-Score |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Email Detector** | Random Forest + TF-IDF Vectorizer | 5,807 emails | **98.80%** | 97.96% | 97.96% | 97.96% |
| **URL Detector** | Random Forest + 8 Lexical Features | 235,795 URLs | **93.78%** | 91.25% | 98.57% | 94.77% |

## How It Works

### 1. Email Analysis

The backend processes submitted email text, applies the configured TF-IDF vectorizer, and uses the trained classification model to generate a prediction.

The system returns:
- Risk score
- Classification
- Detection indicators
- Explanation and recommended actions

### 2. URL Analysis

The URL analyzer extracts structural and lexical features, including:

- URL length
- Number of dots and hyphens
- Presence of @ symbol
- Subdomain count
- IP address detection
- HTTPS usage
- Suspicious keywords

The extracted features are evaluated by the trained URL classification model.

### 3. Explainable Threat Analysis

The frontend presents detection indicators in an understandable format, including why an indicator may be risky and what action a user should consider.

## Installation and Setup

### Requirements

- Python and pip
- Node.js and npm
- Git

### Step 1: Clone Repository

```bash
git clone https://github.com/ankit969348/Phishing-Detection-Explainable-Threat-Analyzer.git

cd Phishing-Detection-Explainable-Threat-Analyzer
```

### Step 2: Setup Backend

```bash
python3 -m venv myphishing

source myphishing/bin/activate

pip install -r requirements.txt

cd phishing_backend

python manage.py check

python manage.py runserver 0.0.0.0:8000
```

Backend API:

`http://127.0.0.1:8000/api/scan/`

### Step 3: Setup Frontend

Open a second terminal:

```bash
cd frontend

npm install

npm run dev -- --host 0.0.0.0
```

Open the frontend:

`http://localhost:5173/`

Keep both backend and frontend terminals running.

## API Usage

Endpoint:

`POST /api/scan/`

Example email request:

```json
{
  "text": "Your account will be suspended. Verify your password immediately."
}
```

Example URL request:

```json
{
  "url": "http://secure-login-verify-account.example.com"
}
```

Example combined request:

```json
{
  "text": "Please verify your account immediately.",
  "url": "http://secure-login-verify-account.example.com"
}
```

## Authentication & Password Recovery Endpoints

- `POST /api/auth/signup/` — Register a new user account and issue a DRF auth token
- `POST /api/auth/login/` — Authenticate user credentials
- `POST /api/auth/logout/` — Invalidate active session token
- `POST /api/auth/send-reset-otp/` — Generate a 6-digit time-bound OTP (10-minute expiry) and dispatch via Gmail SMTP (with offline console fallback)
- `POST /api/auth/reset-password/` — Verify OTP, update password with Django PBKDF2 hashing, and revoke old tokens

## Risk Classification

| Risk Score | Classification |
|---|---|
| 0–39 | Legitimate |
| 40–69 | Suspicious |
| 70–100 | Phishing |

These are automated model assessments, not guarantees of safety or maliciousness.

## Current Limitations

- Email analysis currently focuses on submitted message text.
- Sender authentication using SPF, DKIM, and DMARC is not implemented.
- URL analysis uses extracted URL features.
- Live website inspection and domain reputation checks are not implemented.
- Model predictions may produce false positives and false negatives.
- The project is not independently security-audited or production-hardened.

## Security and Responsible Usage

This project is intended for educational, research, and defensive cybersecurity learning.

- Do not upload passwords, API keys, tokens, or confidential information.
- Never commit `.env` files or private credentials.
- Do not upload personal email data or private datasets.
- Treat suspicious URLs as untrusted.
- Do not rely on a single model prediction for security decisions.
- Use only authorized samples for testing.
- Do not use this project for unauthorized scanning, phishing, or credential collection.

## Learning and Reference

This repository is shared as an educational reference for students and developers interested in:

- Machine Learning-based phishing detection
- Django REST API development
- React frontend integration
- URL feature extraction
- Explainable AI concepts
- Cybersecurity dashboard development

You may study the project for learning purposes. This README does not grant permission to copy, redistribute, or commercially use substantial portions of the source code. Contact the author for permission before reuse.

## Author

**Ankit Kumar Soni**

MCA | Cybersecurity Specialization  
Chanakya University, Bengaluru

GitHub: https://github.com/ankit969348

---

Educational cybersecurity project. Always verify suspicious content through trusted channels.
