"""Loads the trained models once and exposes scan_email() / scan_url().
Enhanced with WHOIS Domain Age verification, Trusted Sender/Domain checks,
Security Disclaimer context filtering, and Zero-Red-Flag probability calibration."""
import re
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

import joblib
import pandas as pd

try:
    import whois
except ImportError:
    whois = None

MODEL_DIR = Path(__file__).resolve().parent.parent / "ml_models"

email_model = joblib.load(MODEL_DIR / "phishing_email_model.pkl")
tfidf = joblib.load(MODEL_DIR / "tfidf_vectorizer.pkl")
url_model = joblib.load(MODEL_DIR / "phishing_url_model.pkl")

URGENCY_WORDS = [
    'urgent', 'immediately', 'verify', 'suspend', 'password',
    'click here', 'act now', 'limited time', 'confirm', 'account'
]

# Legitimate safety disclaimers often included in real bank footers
DISCLAIMER_PATTERNS = [
    r'do not share your .*?(password|otp|pin|cvv|card|details)',
    r'never ask for your .*?(password|otp|pin|cvv)',
    r'system generated communication',
    r'scheduled maintenance',
]

# Established trusted root domains (prevents false positives on official alerts)
TRUSTED_DOMAINS = {
    'axisbank.com', 'axis.bank.in', 'hdfcbank.com', 'icicibank.com', 'sbi.co.in',
    'elevenlabs.io', 'google.com', 'github.com', 'microsoft.com', 'apple.com',
    'amazon.in', 'amazon.com', 'linkedin.com', 'vercel.app', 'supabase.com'
}

# Same column order as used when the URL model was trained in Colab
URL_FEATURE_ORDER = [
    'url_length', 'num_dots', 'num_hyphens', 'num_at',
    'num_subdomains', 'has_ip', 'has_https', 'has_suspicious_word'
]


def clean_text(text):
    text = str(text).lower()
    text = re.sub(r'http\S+|www\S+', ' URLTOKEN ', text)
    text = re.sub(r'[^a-z\s]', ' ', text)
    return re.sub(r'\s+', ' ', text).strip()


def extract_root_domain(host):
    host = (host or '').lower().strip().lstrip('www.')
    if not host or re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
        return host
    parts = host.split('.')
    if len(parts) >= 3 and parts[-2] in {'co', 'bank', 'org', 'gov', 'ac', 'net', 'in'}:
        return '.'.join(parts[-3:])
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return host


def is_trusted_domain(domain):
    root = extract_root_domain(domain)
    return any(root == td or domain.endswith('.' + td) for td in TRUSTED_DOMAINS)


@lru_cache(maxsize=256)
def get_domain_age_info(domain):
    """Returns (age_days, creation_date_str) via WHOIS lookup with safe fallback."""
    root = extract_root_domain(domain)
    if not whois or not root or '.' not in root:
        return None, None
    try:
        w = whois.whois(root)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(creation, datetime):
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - creation).days
            return max(age_days, 0), creation.strftime('%Y-%m-%d')
    except Exception:
        pass
    return None, None


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
    red_flags = []

    # Strip legitimate safety disclaimers before checking urgency/credential keywords
    filtered_text = lower
    has_disclaimer = False
    for pat in DISCLAIMER_PATTERNS:
        if re.search(pat, filtered_text):
            has_disclaimer = True
            filtered_text = re.sub(pat, ' ', filtered_text)

    found_words = [w for w in URGENCY_WORDS if w in filtered_text]
    links = re.findall(r'http\S+|www\S+', lower)

    # Extract sender email domain if pasted from email header/body
    sender_match = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', lower)
    sender_domain = sender_match.group(1) if sender_match else ''
    trusted_sender = is_trusted_domain(sender_domain) if sender_domain else False

    domain_age_days = None
    creation_date_str = None
    if sender_domain:
        domain_age_days, creation_date_str = get_domain_age_info(sender_domain)

    if found_words:
        red_flags.append(f"Urgency/pressure words found: {', '.join(found_words)}")
    if len(links) >= 3:
        red_flags.append(f"Contains {len(links)} links")
    if domain_age_days is not None and domain_age_days < 30:
        red_flags.append(f"Sender domain '{sender_domain}' is newly registered ({domain_age_days} days old)")
        prob = max(prob, 0.75)

    # Calibration & Context Adjustments to prevent False Positives
    if trusted_sender:
        prob *= 0.40
    elif domain_age_days is not None and domain_age_days > 365:
        prob *= 0.65

    if has_disclaimer and not red_flags:
        prob *= 0.45

    # Zero-Red-Flag Calibration: prevent baseline noise from triggering Suspicious
    if not red_flags and prob < 0.65:
        prob = min(prob * 0.65, 0.28)

    prob = round(min(max(prob, 0.01), 0.99), 4)
    res = {
        "risk_score": round(prob * 100, 1),
        "label": risk_label(prob),
        "red_flags": red_flags,
    }
    if sender_domain:
        res["sender_domain"] = sender_domain
    if creation_date_str:
        res["domain_creation_date"] = creation_date_str
        res["domain_age_days"] = domain_age_days
    return res


def scan_url(url):
    feats = url_features(url)
    parsed = urlparse(url if '://' in url else 'http://' + url)
    hostname = parsed.hostname or ''
    root_domain = extract_root_domain(hostname)

    df = pd.DataFrame([feats], columns=URL_FEATURE_ORDER)
    probabilities = url_model.predict_proba(df)[0]
    prob = float(probabilities[list(url_model.classes_).index(0)])

    age_days, creation_date_str = get_domain_age_info(hostname)
    is_established = (age_days is not None and age_days > 365)

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

    # Context-aware keyword & length flags (avoid false positives on established HTTPS domains)
    if feats['has_suspicious_word'] and not is_trusted_domain(hostname):
        if not (is_established and feats['has_https']):
            red_flags.append("Contains suspicious keyword (login/secure/verify/account/bank...)")

    if feats['url_length'] > 75 and not is_trusted_domain(hostname):
        # Long marketing/UTM URLs on established (>1 yr) HTTPS domains are normal
        if not (is_established and feats['has_https']):
            red_flags.append("Very long URL")

    if age_days is not None:
        if age_days < 30:
            red_flags.append(f"Newly registered domain ({age_days} days old, created {creation_date_str})")
            prob = max(prob, 0.82)
        elif age_days < 180:
            red_flags.append(f"Recently registered domain ({age_days} days old, created {creation_date_str})")
            prob = max(prob, 0.55)
        elif is_established:
            prob *= 0.45

    if is_trusted_domain(hostname) and not feats['num_at']:
        prob = min(prob * 0.30, 0.18)
    elif not red_flags:
        # Established or clean URL with no genuine red flags -> Legitimate
        prob = min(prob * 0.25, 0.24)
    elif is_established and not feats['has_ip'] and not feats['num_at']:
        # Established (>1 yr) domain using HTTP or login path -> warn as Suspicious, never Phishing
        prob = min(max(prob, 0.45), 0.58)
    elif len(red_flags) == 1 and prob > 0.68:
        # Single weak signal without newly registered domain -> cap at Suspicious
        prob = min(prob, 0.58)

    prob = round(min(max(prob, 0.01), 0.99), 4)
    res = {
        "risk_score": round(prob * 100, 1),
        "label": risk_label(prob),
        "red_flags": red_flags,
    }
    if root_domain:
        res["domain"] = root_domain
    if creation_date_str:
        res["domain_creation_date"] = creation_date_str
        res["domain_age_days"] = age_days
    return res
