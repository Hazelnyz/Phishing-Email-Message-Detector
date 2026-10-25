"""
app.py
-------
Flask web application for PhishGuard AI.

Routes:
  /                -> Home
  /analyze         -> Message Analysis (GET form, POST result)
  /performance      -> Model Performance (reads evaluation/metrics.json)
  /awareness        -> Phishing Awareness education page
  /about            -> About page
  /api/analyze      -> JSON API endpoint (POST) used by the analysis page's JS

Security notes:
  - All user input is rendered through Jinja2 autoescaping (Flask default),
    which escapes HTML/JS in user-provided content.
  - No URL found in a message is ever fetched, opened, or visited by the
    server. URL strings are parsed locally only (see src/signal_detector.py).
  - The app never asks the user for, stores, or transmits a password or OTP.
  - Basic input length validation is applied server-side.
"""

import os
import json
from flask import Flask, render_template, request, jsonify

from src.risk_engine import classify_risk
from src import chat_service
from config import REPORTING_CONTACTS

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EVAL_DIR = os.path.join(BASE_DIR, "evaluation")
MODEL_DIR = os.path.join(BASE_DIR, "models")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024  # 64 KB max request body

MAX_MESSAGE_LEN = 5000


def load_metrics():
    path = os.path.join(EVAL_DIR, "metrics.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


@app.route("/")
def home():
    metrics = load_metrics()
    return render_template("home.html", metrics=metrics)


@app.route("/analyze", methods=["GET", "POST"])
def analyze():
    result = None
    error = None
    message = ""
    sender = ""
    url_hint = ""

    if request.method == "POST":
        message = (request.form.get("message") or "").strip()
        sender = (request.form.get("sender") or "").strip()
        url_hint = (request.form.get("url_hint") or "").strip()

        if not message:
            error = "Please enter a message to analyze."
        elif len(message) > MAX_MESSAGE_LEN:
            error = f"Message is too long (max {MAX_MESSAGE_LEN} characters)."
        else:
            try:
                result = classify_risk(message, sender=sender or None, url_hint=url_hint or None)
            except FileNotFoundError:
                error = ("The ML model has not been trained yet. Run "
                          "`python run_pipeline.py` first.")

    return render_template(
        "analyze.html", result=result, error=error,
        message=message, sender=sender, url_hint=url_hint,
    )


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    sender = (data.get("sender") or "").strip() or None
    url_hint = (data.get("url_hint") or "").strip() or None

    if not message:
        return jsonify({"error": "message is required"}), 400
    if len(message) > MAX_MESSAGE_LEN:
        return jsonify({"error": f"message too long (max {MAX_MESSAGE_LEN} chars)"}), 400

    try:
        result = classify_risk(message, sender=sender, url_hint=url_hint)
    except FileNotFoundError:
        return jsonify({"error": "model not trained yet"}), 503

    return jsonify(result)


@app.route("/performance")
def performance():
    metrics = load_metrics()
    return render_template("performance.html", metrics=metrics)


@app.route("/api/metrics")
def api_metrics():
    metrics = load_metrics()
    if metrics is None:
        return jsonify({"error": "evaluation metrics are not available"}), 404
    return jsonify(metrics)


@app.route("/api/chat/status", methods=["GET"])
def chat_status_api():
    return jsonify(chat_service.chat_status())


@app.route("/api/chat", methods=["POST"])
def chat_api():
    if not request.is_json:
        return jsonify({"error": "Request must use application/json."}), 400
    payload = request.get_json(silent=True)
    error = chat_service._validate_chat_payload(payload)
    if error:
        return jsonify({"error": error}), 400
    client_ip = request.remote_addr or "unknown"
    if not chat_service.allow_request(client_ip):
        return jsonify({"error": "Chat rate limit reached. Try again in a minute."}), 429
    return jsonify(chat_service.handle_chat(payload)), 200


@app.route("/awareness")
def awareness():
    return render_template("awareness.html", reporting_contacts=REPORTING_CONTACTS)


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Page not found."), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Something went wrong."), 500


if __name__ == "__main__":
    # debug=False by default for safety; set FLASK_DEBUG=1 env var for local dev if desired
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    host = os.environ.get("APP_HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    app.run(host=host, port=port, debug=debug_mode)
