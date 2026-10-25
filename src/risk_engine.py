"""
risk_engine.py
---------------
Combines the ML model's prediction with the rule-based signal detector to
produce a final risk classification: HIGH RISK, MEDIUM RISK, LOW RISK, or
INSUFFICIENT INFORMATION.

Design notes:
- The ML model gives a probabilistic phishing/legitimate prediction learned
  from text patterns.
- The signal detector gives explainable, rule-based evidence (urgency,
  threats, credential requests, suspicious URLs, sender mismatch, payment
  requests).
- The two are combined into a single 0-100 risk score. Neither source alone
  decides the label — this keeps the system more robust and explainable than
  the ML model alone, and avoids over-trusting a small synthetic model.
- LOW RISK is never presented as a guarantee of safety; the UI and the report
  both state this explicitly.
"""

import os
import joblib
import re

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "models")

_vectorizer = None
_model = None
_model_name = None
_model_threshold = 0.5
_domain_artifacts = None


def _defang(value):
    if re.match(r"(?i)^(?:https?://|www\.)", value):
        value = re.sub(r"(?i)https?://", lambda m: "hxxps://" if m.group(0).lower().startswith("https") else "hxxp://", value)
        return value.replace(".", "[.]")
    return value


def normalize_email_for_model(message):
    """Apply the exact cleaner used before fitting the email TF-IDF model."""
    from src.data_loader_email import clean_email_text
    return clean_email_text(message)


def _load_artifacts():
    global _vectorizer, _model, _model_name, _model_threshold
    if _vectorizer is None or _model is None:
        vec_path = os.path.join(MODEL_DIR, "tfidf_vectorizer.joblib")
        model_path = os.path.join(MODEL_DIR, "best_model.joblib")
        if not (os.path.exists(vec_path) and os.path.exists(model_path)):
            raise FileNotFoundError(
                "Model artifacts not found. Run `python src/train_model.py` first."
            )
        _vectorizer = joblib.load(vec_path)
        _model = joblib.load(model_path)

        import json
        info_path = os.path.join(MODEL_DIR, "best_model_info.json")
        if os.path.exists(info_path):
            with open(info_path) as f:
                info = json.load(f)
                _model_name = info.get("best_model_name", "Unknown")
                _model_threshold = float(info.get("threshold", 0.5))
        else:
            _model_name = type(_model).__name__
    return _vectorizer, _model

def _predict_domain_models(message):
    """Use the phase-specific trained artifacts when available."""
    global _domain_artifacts
    email_vec=os.path.join(MODEL_DIR,"email_vectorizer.joblib")
    email_model=os.path.join(MODEL_DIR,"email_best_model.joblib")
    url_vec=os.path.join(MODEL_DIR,"url_vectorizer.joblib")
    url_model=os.path.join(MODEL_DIR,"url_best_model.joblib")
    if not (os.path.exists(email_vec) and os.path.exists(email_model)):
        return None
    import json
    if _domain_artifacts is None:
        ev=joblib.load(email_vec); em=joblib.load(email_model)
        with open(os.path.join(MODEL_DIR,"email_best_info.json"),encoding="utf-8") as f: ei=json.load(f)
        uv=um=ui=None
        if os.path.exists(url_vec) and os.path.exists(url_model):
            uv=joblib.load(url_vec); um=joblib.load(url_model)
            with open(os.path.join(MODEL_DIR,"url_best_info.json"),encoding="utf-8") as f: ui=json.load(f)
        _domain_artifacts=(ev,em,ei,uv,um,ui)
    ev,em,ei,uv,um,ui=_domain_artifacts
    url_match=re.findall(r'(?:https?://|www\.)[^\s<>"\']+',message,re.I)
    probabilities=[]; names=[]; thresholds=[]
    text_without_urls=re.sub(r'(?:https?://|www\.)[^\s<>"\']+',' ',message,flags=re.I).strip()
    if text_without_urls and len(text_without_urls.split())>=2:
        ex=ev.transform([normalize_email_for_model(message)]); probabilities.append(float(em.predict_proba(ex)[0,list(em.classes_).index(1)])); names.append(ei.get('model','Email classifier'))
        thresholds.append(float(ei.get('threshold',.5)))
    if url_match and uv is not None and um is not None:
        from src.url_features import url_features
        for raw in url_match:
            raw=raw.rstrip('.,;:!?)')
            probabilities.append(float(um.predict_proba(uv.transform([url_features(raw)]))[0,list(um.classes_).index(1)])); names.append(ui.get('model','URL classifier')); thresholds.append(float(ui.get('threshold',.5)))
    if not probabilities:return None
    threshold=sum(thresholds)/len(thresholds)
    return {'prediction':'phishing' if sum(probabilities)/len(probabilities)>=threshold else 'legitimate','probabilities':{'phishing':sum(probabilities)/len(probabilities),'legitimate':1-sum(probabilities)/len(probabilities)},'model_name':' + '.join(sorted(set(names))),'threshold':threshold}


def ml_predict(message: str):
    phase_prediction=_predict_domain_models(message)
    if phase_prediction is not None:return phase_prediction
    vectorizer, model = _load_artifacts()
    X = vectorizer.transform([normalize_email_for_model(message)])
    pred = model.predict(X)[0]
    proba = None
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(X)[0]
        classes = list(model.classes_)
        proba = dict(zip(classes, probs.tolist()))
        pred = "phishing" if proba.get("phishing", 0) >= _model_threshold else "legitimate"
    return {
        "prediction": pred,
        "probabilities": proba,
        "model_name": _model_name,
    }


def _probability_to_ml_points(probability, threshold):
    """Monotonically map the validation threshold to the 25-point midpoint."""
    p = max(0.0, min(1.0, float(probability)))
    t = float(threshold)
    if not 0.0 < t < 1.0:
        return p * 50.0
    midpoint = 50.0 / 2.0
    if p == t:
        return midpoint
    if p <= t:
        return midpoint * p / t
    return midpoint + midpoint * (p - t) / (1.0 - t)


def classify_risk(message: str, sender: str = None, url_hint: str = None):
    from src.signal_detector import detect_signals  # local import to avoid circularity in tests

    message = (message or "").strip()

    signal_result = detect_signals(message, sender=sender, url_hint=url_hint)
    if len(message.split()) < 5 and not signal_result["signals"]:
        return {
            "risk_level": "INSUFFICIENT INFORMATION",
            "risk_score": 0,
            "ml": None,
            "signals": [],
            "explanation": "The message is too short or empty to analyse reliably. "
                            "Please provide the full text of the message.",
            "recommendations": [
                "Paste the complete message text, including any links, for an accurate analysis."
            ],
        }

    ml_result = ml_predict(message)

    # Map the validation-selected threshold to the midpoint of the ML points.
    ml_score = 0
    if ml_result["probabilities"]:
        threshold = ml_result.get("threshold", _model_threshold)
        ml_score = _probability_to_ml_points(ml_result["probabilities"].get("phishing", 0), threshold)
    else:
        ml_score = 50 if ml_result["prediction"] == "phishing" else 0

    # Rule-based contribution: signal weights, capped at 50
    rule_score = min(signal_result["total_weight"], 50)

    total_score = round(ml_score + rule_score, 1)
    total_score = max(0, min(100, total_score))

    if total_score >= 65:
        risk_level = "HIGH RISK"
    elif total_score >= 35:
        risk_level = "MEDIUM RISK"
    else:
        risk_level = "LOW RISK"

    # High-severity evidence is a hard floor, independent of model probability.
    high_floor_categories = {"Credential / OTP Request", "Suspicious Payment / Financial Request", "Suspicious URL"}
    high_severity = any(s.get("severity") in {"high", "critical"} or s.get("category") in high_floor_categories
                        for s in signal_result["signals"])
    if high_severity and risk_level == "LOW RISK":
        risk_level = "MEDIUM RISK"
        total_score = max(total_score, 35)

    displayed_signals = [dict(s, evidence=[_defang(v) for v in s.get("evidence", [])]) for s in signal_result["signals"]]
    strongest_signals = sorted(displayed_signals, key=lambda s: -s["weight"])[:3]

    recommendations = build_recommendations(risk_level, signal_result)

    explanation = build_explanation(ml_result, signal_result, risk_level)

    return {
        "risk_level": risk_level,
        "risk_score": total_score,
        "ml": ml_result,
        "signals": displayed_signals,
        "strongest_signals": strongest_signals,
        "url_findings": [dict(f, url=_defang(f["url"])) for f in signal_result["url_findings"]],
        "sender_check": signal_result["sender_check"],
        "explanation": explanation,
        "recommendations": recommendations,
    }


def build_explanation(ml_result, signal_result, risk_level):
    parts = []
    model_name = ml_result.get("model_name", "the ML model")
    pred = ml_result["prediction"]
    probs = ml_result.get("probabilities")
    if probs:
        p_phish = probs.get("phishing", 0) * 100
        parts.append(
            f"The trained {model_name} classifier predicts this message is "
            f"'{pred}' with an estimated {p_phish:.1f}% phishing probability."
        )
    else:
        parts.append(f"The trained {model_name} classifier predicts this message is '{pred}'.")

    n_signals = len(signal_result["signals"])
    if n_signals:
        cats = ", ".join(s["category"] for s in signal_result["signals"])
        parts.append(f"{n_signals} rule-based warning signal(s) were found: {cats}.")
    else:
        parts.append("No rule-based warning signals were found in the message text.")

    if risk_level == "LOW RISK":
        parts.append(
            "This message shows few or no phishing indicators, but a LOW RISK rating is not a "
            "guarantee of safety — always verify unexpected requests through an official channel."
        )

    return " ".join(parts)


def build_recommendations(risk_level, signal_result):
    recs = []
    cats = {s["category"] for s in signal_result["signals"]}

    if risk_level == "HIGH RISK":
        recs.append("Do not click any links, reply, or provide any information.")
        recs.append("Report this message to your institution's official IT security contact through a "
                     "channel you already trust (not a contact found in this message).")
        recs.append("Delete or block the sender after reporting.")
    elif risk_level == "MEDIUM RISK":
        recs.append("Treat this message with caution — do not click links or share information yet.")
        recs.append("Independently verify the request by contacting the organisation using a phone "
                     "number or website you already know to be correct, not one from this message.")
    else:
        recs.append("No strong phishing indicators were found, but stay cautious with unexpected requests.")
        recs.append("Never enter your password or OTP on a page reached through a message link.")

    if "Credential / OTP Request" in cats:
        recs.append("Remember: legitimate organisations never ask you to send your password or OTP "
                     "over chat, SMS, or email.")
    if "Suspicious URL" in cats:
        recs.append("Do not visit the link in this message. If you need to reach the service, type the "
                     "official website address directly into your browser instead.")
    if "Suspicious Payment / Financial Request" in cats:
        recs.append("Do not transfer money or share banking/UPI details based on this message alone.")

    return recs
