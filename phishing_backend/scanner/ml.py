"""Loads the trained models once and exposes scan_email() / scan_url().
Enhanced with Multi-Part TLD (.edu.in/.gov.in) parsing, WHOIS Domain Age verification,
Context-Aware Risk Calibration, and Clean Legitimate Explanations."""
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

DISCLAIMER_PATTERNS = [
    r'do not share your .*?(password|otp|pin|cvv|card|details)',
    r'never ask for your .*?(password|otp|pin|cvv)',
    r'system generated communication',
    r'scheduled maintenance',
]

TRUSTED_DOMAINS = {
    'axisbank.com', 'axis.bank.in', 'hdfcbank.com', 'icicibank.com', 'sbi.co.in',
    'elevenlabs.io', 'google.com', 'github.com', 'microsoft.com', 'apple.com',
    'amazon.in', 'amazon.com', 'linkedin.com', 'vercel.app', 'supabase.com',
    'testrigor.com', 'chanakyauniversity.edu.in'
}

SECOND_LEVEL_TLDS = {'co', 'bank', 'org', 'gov', 'ac', 'net', 'in', 'edu', 'nic', 'res'}

HIGH_RISK_TLDS = (
    '.xyz', '.top', '.club', '.online', '.site', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.buzz'
)

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
    host = (host or '').lower().strip().rstrip('.')
    if host.startswith('www.'):
        host = host[4:]
    if not host or re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
        return host
    parts = [p for p in host.split('.') if p]
    if len(parts) >= 3 and parts[-2] in SECOND_LEVEL_TLDS:
        return '.'.join(parts[-3:])
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return host


def count_real_subdomains(host, root_domain):
    host = (host or '').lower().strip().rstrip('.')
    if host.startswith('www.'):
        host = host[4:]
    if not host or not root_domain or host == root_domain:
        return 0
    if host.endswith('.' + root_domain):
        prefix = host[:-(len(root_domain) + 1)]
        return len([p for p in prefix.split('.') if p])
    return max(host.count('.') - 1, 0)


def is_trusted_domain(domain):
    h = (domain or '').lower().strip().rstrip('.')
    root = extract_root_domain(h)
    if h.endswith(('.edu', '.edu.in', '.ac.in', '.gov', '.gov.in', '.nic.in', '.ac.uk', '.gov.uk')):
        return True
    return any(root == td or h == td or h.endswith('.' + td) for td in TRUSTED_DOMAINS)


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

    filtered_text = lower
    has_disclaimer = False
    for pat in DISCLAIMER_PATTERNS:
        if re.search(pat, filtered_text):
            has_disclaimer = True
            filtered_text = re.sub(pat, ' ', filtered_text)

    found_words = [w for w in URGENCY_WORDS if w in filtered_text]
    links = re.findall(r'http\S+|www\S+', lower)

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
    if domain_age_days is not None and domain_age_days < 30 and not trusted_sender:
        red_flags.append(f"Sender domain '{sender_domain}' is newly registered ({domain_age_days} days old)")
        prob = max(prob, 0.75)

    if trusted_sender:
        prob *= 0.40
    elif domain_age_days is not None and domain_age_days > 365:
        prob *= 0.65

    if has_disclaimer and not red_flags:
        prob *= 0.45

    if not red_flags and prob < 0.65:
        prob = min(prob * 0.65, 0.28)

    prob = round(min(max(prob, 0.01), 0.99), 4)
    final_label = risk_label(prob)
    if final_label == "legitimate":
        red_flags = []

    res = {
        "risk_score": round(prob * 100, 1),
        "label": final_label,
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
    hostname = (parsed.hostname or '').lower()
    root_domain = extract_root_domain(hostname)
    real_subdomains = count_real_subdomains(hostname, root_domain)
    trusted = is_trusted_domain(hostname)
    high_risk_tld = hostname.endswith(HIGH_RISK_TLDS)

    df = pd.DataFrame([feats], columns=URL_FEATURE_ORDER)
    probabilities = url_model.predict_proba(df)[0]
    prob = float(probabilities[list(url_model.classes_).index(0)])

    age_days, creation_date_str = get_domain_age_info(root_domain or hostname)
    is_established = (age_days is not None and age_days > 365)

    base_url_len = len(url.split('?')[0])
    is_marketing_query = any(k in parsed.query.lower() for k in ['utm_', 'ref=', 'eid=', 'gclid=', 'fbclid=', 'si='])

    red_flags = []
    if feats['has_ip']:
        red_flags.append("Uses an IP address instead of a domain name")
    if not feats['has_https']:
        red_flags.append("Does not use HTTPS")
    if feats['num_at']:
        red_flags.append("Contains '@' symbol")
    if high_risk_tld:
        red_flags.append("Uses high-risk domain extension")
    if root_domain.count('-') >= 2 and not trusted:
        red_flags.append("Many hyphens in domain name")
    if real_subdomains >= 3 and not trusted:
        red_flags.append("Unusually many subdomains")

    if feats['has_suspicious_word'] and not trusted:
        if not (is_established and feats['has_https']):
            red_flags.append("Contains suspicious keyword (login/secure/verify/account/bank...)")

    # Long path/query alone on an HTTPS site without other red flags is not phishing
    if base_url_len > 95 and not trusted and not is_established and not is_marketing_query:
        red_flags.append("Very long URL")

    if age_days is not None:
        if age_days < 30 and not trusted:
            red_flags.append(f"Newly registered domain ({age_days} days old, created {creation_date_str})")
            prob = max(prob, 0.82)
        elif age_days < 180 and not trusted:
            red_flags.append(f"Recently registered domain ({age_days} days old, created {creation_date_str})")
            prob = max(prob, 0.55)
        elif is_established:
            prob *= 0.30

    if trusted and feats['has_https'] and not feats['num_at'] and not feats['has_ip']:
        prob = min(prob * 0.20, 0.14)
    elif not red_flags:
        # Clean HTTPS domain with no genuine red flags -> Legitimate
        prob = min(prob * 0.20, 0.20)
    elif is_established and not feats['has_ip'] and not feats['num_at'] and not high_risk_tld:
        # Established (>1 yr) domain using HTTP or login path -> Suspicious warning, never Phishing
        prob = min(max(prob, 0.45), 0.55)
    elif len(red_flags) == 1 and prob > 0.68:
        prob = min(prob, 0.55)

    prob = round(min(max(prob, 0.01), 0.99), 4)
    final_label = risk_label(prob)

    # Do not display scary red-flag cards when the final verdict is Legitimate
    if final_label == "legitimate":
        red_flags = []

    res = {
        "risk_score": round(prob * 100, 1),
        "label": final_label,
        "red_flags": red_flags,
    }
    if root_domain:
        res["domain"] = root_domain
    if creation_date_str:
        res["domain_creation_date"] = creation_date_str
        res["domain_age_days"] = age_days
    return res
