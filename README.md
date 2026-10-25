# PhishGuard AI

AI-based phishing message detection and awareness system, built in response to a
hypothetical scenario (16 October 2026) in which students reported messages
claiming their VIT accounts would be suspended unless they clicked a link
immediately.

PhishGuard AI combines a trained machine-learning text classifier (TF-IDF +
Logistic Regression / Multinomial Naive Bayes) with an explainable, rule-based
phishing signal detector, and presents results through a Flask web dashboard.

> **Disclaimer:** This is an educational project, not an official VIT system.
> Training uses the datasets described in `DATASET_CARD.md`. This tool
> never asks for, stores, or transmits your password or OTP, and never opens
> or visits any URL — links are analysed as text only.

---

## Project structure

```
PhishGuard-AI/
├── app.py                     # Flask application (routes)
├── requirements.txt
├── README.md
├── DATASET_README.md
├── docs/
│   ├── PROJECT_REPORT.md
│   └── VIVA_QUESTIONS.md
├── src/
│   ├── generate_dataset.py    # Synthetic dataset generator
│   ├── train_model.py         # Trains & evaluates NB + Logistic Regression
│   ├── signal_detector.py     # Rule-based phishing signal detection
│   └── risk_engine.py         # Combines ML + signals into a risk rating
├── data/                      # Small project fixtures; raw corpora are excluded
├── models/                    # Required, saved classifiers and vectorizers
├── evaluation/metrics.json    # Runtime metrics used by the performance page
├── templates/                 # Jinja2 HTML templates
├── static/                    # CSS / JS / chart image
└── tests/                     # pytest test suite
```

---

## Requirements

- Python 3.10 or later
- pip
- Windows, macOS, or Linux (commands below are given for Windows PowerShell,
  as requested; Linux/macOS users can use the equivalent `python3` / `source`
  commands)

---

## Setup & run — Windows PowerShell (exact commands)

Open PowerShell in the project folder (`PhishGuard-AI`) and run:

```powershell
# 1. Create and activate a virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# If PowerShell blocks script execution, run this once (as the current user):
# Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the automated test suite
python -m pytest

# 4. Start the Flask development server
python app.py
```

Then open your browser to **http://127.0.0.1:5000**.

To stop the server, press `Ctrl+C` in the PowerShell window.

To deactivate the virtual environment when done:
```powershell
deactivate
```

---

## Setup & run — macOS / Linux (equivalent commands)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 -m pytest
python3 app.py
```

The checked-in model artifacts and `evaluation/metrics.json` are used at
runtime. Raw training corpora are intentionally excluded from Git. To retrain
or reproduce the full evaluation pipeline, obtain the authorized datasets
locally and follow the evaluation notes below.

## Render deployment

The repository includes a Render Blueprint in `render.yaml`. After you approve
and push the project to a GitHub repository, create a Render Blueprint from
that repository. Render installs `requirements.txt` and starts the Flask WSGI
application with Gunicorn. `CHAT_ENABLED` is set to `false` because a hosted
service cannot use your private local Ollama instance; classification remains
available and chat returns a fixed phishing-safety fallback. Do not configure
a public Ollama address or commit credentials. Optional institutional
reporting details can be configured with `INSTITUTION_NAME`,
`SECURITY_TEAM_CONTACT`, and `SECURITY_REPORTING_URL` in the Render dashboard.

For manual Render setup, use build command `pip install -r requirements.txt`
and this start command:

```text
gunicorn --bind 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 120 app:app
```

---

## Using the application

1. **Home** — overview and key stats.
2. **Message Analysis** — paste a message (and optionally a sender/domain or
   extra URL) to get a HIGH / MEDIUM / LOW RISK / INSUFFICIENT INFORMATION
   rating, model prediction, flagged signals, and safe recommendations.
3. **Model Performance** — real accuracy/precision/recall/F1 and confusion
   matrices for both trained classifiers, plus a comparison chart.
4. **Phishing Awareness** — general guidance on recognising and responding to
   phishing attempts, including the October 2026 scenario.

A JSON API is also available: `POST /api/analyze` with `{"message": "...", "sender": "...", "url_hint": "..."}`.

---

## Regenerating everything

The dataset generator is seeded (`random.seed(42)`), so re-running it
reproduces the same synthetic data. Training overwrites saved model artifacts
and metrics; do not run it for a deployment build.

## Evaluation method and current measured results

`run_pipeline.py` trains email and URL classifiers from the locally supplied files under
`data/raw/`, holds out inferred email template families, deduplicates URLs before
splitting, performs five-fold email cross-validation, and selects classifiers
and thresholds using validation splits only. The independent email validation
corpus and handwritten hard test are evaluated after selection. URL inputs are
never fetched or resolved. SMS is skipped when no CSV is present.

Metrics shown in the UI are read from `evaluation/metrics.json`. Training output
is written to `evaluation/terminal_run.txt`; privacy-masked errors are in
`evaluation/errors.csv`. See `DATASET_CARD.md` for sources and limitations.

---

## Security notes

- No URL submitted to the tool is ever fetched or visited by the server —
  only parsed as a string (see `src/signal_detector.py`).
- User input is rendered through Jinja2's automatic HTML-escaping, which
  prevents stored/reflected XSS from analysed message text.
- The app never requests, stores, or transmits a password or OTP.
- Request body size is capped (64 KB) and message length is validated
  server-side (max 5000 characters).

See `docs/PROJECT_REPORT.md` for a full write-up and `docs/VIVA_QUESTIONS.md`
for viva questions and answers.

## Optional local assistant (Ollama)

The floating PhishGuard Assistant can explain an analysis result using a local
Ollama service. The app and its risk analysis continue to work normally when
Ollama is not installed or running. From a terminal, install and start Ollama,
then pull the suggested local model:

```powershell
ollama pull llama3.2:3b
```

Keep Ollama running on its local default address. The app prefers
`llama3.2:3b`, then `llama3.2:1b`, then another installed model. Optional
environment variables are `OLLAMA_HOST` (default `http://127.0.0.1:11434`),
`OLLAMA_MODEL` (default `auto`), and `CHAT_ENABLED` (default `true`). Only
loopback Ollama hosts are accepted. The assistant explains the existing
pipeline result and cannot change its risk label; without Ollama, the normal
analysis pages remain available and the chat returns fixed safety advice.
