
"""Loads the trained models once and exposes scan_email() / scan_url().
The cleaning + feature functions are copied EXACTLY from the Colab notebook,
because the models only work if inputs are prepared the same way as in training."""
import re
from pathlib import Path
from urllib.parse import urlparse

import joblib
import pandas as pd

MODEL_DIR = Path(__file__).resolve().parent.parent / "ml_models"

email_model = joblib.load(MODEL_DIR / "phishing_email_model.pkl")
tfidf = joblib.load(MODEL_DIR / "tfidf_vectorizer.pkl")
url_model = joblib.load(MODEL_DIR / "phishing_url_model.pkl")

URGENCY_WORDS = ['urgent', 'immediately', 'verify', 'suspend', 'password',
                 'click here', 'act now', 'limited time', 'confirm', 'account']

# Same column order as used when the URL model was trained in Colab
URL_FEATURE_ORDER = ['url_length', 'num_dots', 'num_hyphens', 'num_at',
                     'num_subdomains', 'has_ip', 'has_https', 'has_suspicious_word']


def clean_text(text):
    text = str(text).lower()
    text = re.sub(r'http\S+|www\S+', ' URLTOKEN ', text)
    text = re.sub(r'[^a-z\s]', ' ', text)
    return re.sub(r'\s+', ' ', text).strip()


def url_features(url):
    url = str(url).strip()
    parsed = urlparse(url if '://' in url else 'http://' + url)
    hostname = parsed.hostname or ''
    return {
        'url_length': len(url),
        'num_dots': url.count('.'),
        'num_hyphens': url.count('-'),
        'num_at': url.count('@'),
        'num_subdomains': hostname.count('.'),
        'has_ip': 1 if re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname) else 0,
        'has_https': 1 if url.lower().startswith('https') else 0,
        'has_suspicious_word': 1 if re.search(r'login|secure|update|verify|account|bank', url.lower()) else 0,
    }


def risk_label(prob):
    if prob >= 0.70:
        return "phishing"
    if prob >= 0.40:
        return "suspicious"
    return "legitimate"


def scan_email(text):
    vec = tfidf.transform([clean_text(text)])
    prob = float(email_model.predict_proba(vec)[0][1])

    lower = text.lower()
    found_words = [w for w in URGENCY_WORDS if w in lower]
    links = re.findall(r'http\S+|www\S+', lower)
    red_flags = []
    if found_words:
        red_flags.append(f"Urgency/pressure words found: {', '.join(found_words)}")
    if len(links) >= 3:
        red_flags.append(f"Contains {len(links)} links")

    return {"risk_score": round(prob * 100, 1), "label": risk_label(prob), "red_flags": red_flags}


def scan_url(url):
    feats = url_features(url)
    df = pd.DataFrame([feats], columns=URL_FEATURE_ORDER)
    probabilities = url_model.predict_proba(df)[0]
    prob = float(probabilities[list(url_model.classes_).index(0)])

    red_flags = []
    if feats['has_ip']:
        red_flags.append("Uses an IP address instead of a domain name")
    if not feats['has_https']:
        red_flags.append("Does not use HTTPS")
    if feats['num_at']:
        red_flags.append("Contains '@' symbol")
    if feats['num_hyphens'] >= 3:
        red_flags.append("Many hyphens in URL")
    if feats['num_subdomains'] >= 3:
        red_flags.append("Unusually many subdomains")
    if feats['has_suspicious_word']:
        red_flags.append("Contains suspicious keyword (login/secure/verify/account/bank...)")
    if feats['url_length'] > 75:
        red_flags.append("Very long URL")

    return {"risk_score": round(prob * 100, 1), "label": risk_label(prob), "red_flags": red_flags}

