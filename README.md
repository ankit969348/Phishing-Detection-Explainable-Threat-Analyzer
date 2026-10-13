# Phishing Detection: Explainable Threat Analyzer
Explainable phishing detector for emails and URLs: ML classifiers (Random Forest) plus rule-based red flags,
served through a Django REST API (POST /api/scan/).

- phishing_backend/ : Django REST backend (scanner app, ml_models)
- notebooks/        : Colab notebook (training pipeline)
- docs/             : project documentation and research paper

Models: email Random Forest (97.9% accuracy), URL Random Forest (94.6% accuracy).
Datasets: Kaggle email dataset and a PhishTank / Phishing URL dataset (not included, too large).
