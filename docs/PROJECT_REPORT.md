# Project Report — PhishGuard AI

## 1. Problem statement and scenario

On 16 October 2026 (hypothetical scenario), students reported receiving
messages claiming their VIT accounts would be suspended unless they clicked a
link immediately — a classic urgency-and-threat phishing pattern. PhishGuard
AI was built as an educational response: a tool that analyses message text
and gives students an explainable, actionable risk assessment before they act
on a suspicious request.

## 2. Objectives

1. Detect phishing indicators in free-text messages using both machine
   learning and explainable rule-based heuristics.
2. Classify risk into HIGH / MEDIUM / LOW RISK, or INSUFFICIENT INFORMATION
   when there isn't enough text to judge.
3. Explain *why* a message was flagged, not just output a label.
4. Never put the user at risk in the process of analysis (no URL fetching, no
   credential collection).
5. Provide a usable, professional web dashboard for message analysis and
   model performance transparency.

## 3. System architecture

```
 User message ──┬──► TF-IDF vectorizer ──► Trained classifier ──► phishing probability
                │
                └──► Rule-based signal detector ──► weighted signal list
                                     │
                                     ▼
                           Risk Engine (combines both)
                                     │
                                     ▼
                     Risk level + score + explanation + recommendations
                                     │
                                     ▼
                              Flask web dashboard
```

- **`src/generate_dataset.py`** — produces a synthetic, labelled dataset of
  phishing and legitimate messages (see `DATASET_README.md`).
- **`src/train_model.py`** — fits a TF-IDF vectorizer on the training split
  only, trains Multinomial Naive Bayes and Logistic Regression classifiers,
  evaluates both on a held-out test split, and saves the better-performing
  model (by F1-score on the phishing class).
- **`src/signal_detector.py`** — regex/heuristic-based detector for urgency,
  threats, credential/OTP requests, suspicious URLs, sender mismatch, and
  payment requests. URL analysis is purely string-based (host, TLD, path) —
  **no network requests are made**.
- **`src/risk_engine.py`** — combines the ML model's phishing probability
  (up to 50 points) with the rule-based signal weight (up to 50 points) into
  a single 0–100 score, and maps it to a risk level with an explanation and
  recommended actions.
- **`app.py`** + **`templates/`** — Flask web application exposing Home,
  Message Analysis, Model Performance, Phishing Awareness, and About pages,
  plus a JSON API (`/api/analyze`).

## 4. Dataset

- Synthetic generated messages are listed in `data/messages_full.csv`.
- Training, validation, template-family held-out, and hard-test split counts
  are published from `evaluation/metrics.json` in `RESULTS_SUMMARY.md`.
- Template families are separated before fitting; the handwritten hard test
  is excluded from model and threshold selection.
- Full documentation and limitations are in `DATASET_README.md`.

## 5. Model training and evaluation

Both models use TF-IDF features fitted on the training split. Evaluation holds
out complete template families and uses a separate handwritten hard test.
Current metrics, confusion matrices, cross-validation results, and model
selection are generated from `evaluation/metrics.json`; see
[`RESULTS_SUMMARY.md`](RESULTS_SUMMARY.md). The hard test is excluded from
training, threshold selection, and model selection.

**Important caveat:** source-specific artifacts can inflate scores, and the
handwritten hard test is small. A production system would need a larger and
more linguistically diverse, human-labelled dataset, plus evaluation against
adversarial and novel phishing text, before these numbers could be taken as
representative of real-world performance.

## 6. Risk scoring design

- ML contribution: `phishing_probability × 50` (0–50 points).
- Rule-based contribution: sum of triggered signal weights, capped at 50
  points. Signal weights range from 5 (a present-but-unremarkable link) to 30
  (a direct credential/OTP request).
- Combined score (0–100) maps to:
  - **HIGH RISK**: score ≥ 65
  - **MEDIUM RISK**: 35 ≤ score < 65
  - **LOW RISK**: score < 35
  - **INSUFFICIENT INFORMATION**: fewer than five words with no detected signal
- A LOW RISK result is always paired with a disclaimer that it is not a
  safety guarantee.

## 7. Security considerations

- URLs are parsed with Python's `urllib.parse` only; the application never
  issues an HTTP request to a URL found in a message.
- The UI explicitly states the tool will never ask for a password or OTP.
- Jinja2 autoescaping prevents injected HTML/JS in submitted messages from
  executing in the rendered page (verified by `tests/test_flask_routes.py::test_message_is_escaped_in_rendered_html`).
- Request body size and message length are capped server-side.
- No real reporting contact details are fabricated; the awareness guidance
  tells users to use channels they already know and trust.

## 8. Testing

42 automated pytest tests across four files cover:
- Signal detector correctness (`tests/test_signal_detector.py`) — including a
  test that asserts no network socket is ever opened during URL analysis.
- Risk engine behaviour and score bounds (`tests/test_risk_engine.py`).
- Dataset integrity and model artifact validity, including an explicit
  train/test overlap (data-leakage) check (`tests/test_model_training.py`).
- Flask routes, form handling, the JSON API, and XSS-escaping
  (`tests/test_flask_routes.py`).

All 42 tests passed in the most recent run (see terminal output captured
during development; re-run with `pytest tests/ -v` to verify locally).

## 9. Limitations and future work

- Synthetic, template-based dataset (see `DATASET_README.md`) limits
  real-world generalisation; a larger, diverse, human-verified dataset would
  be the top priority for a production version.
- No sender-authentication/SPF/DKIM checking (metadata-based checks are
  limited to a provided sender string, since full email headers are not
  collected).
- No persistence layer — each analysis is stateless; a production system
  might log flagged messages (with consent/privacy safeguards) to improve
  the model over time.
- Could be extended with multilingual support, an email/browser-extension
  front-end, and periodic retraining on newly confirmed phishing samples.

## 10. Conclusion

PhishGuard AI demonstrates an end-to-end, explainable phishing-detection
pipeline — from synthetic dataset generation, through dual-classifier
training and evaluation, to a risk-scoring engine and a usable web dashboard
— built with safety (no URL fetching, no credential collection) and
transparency (real evaluation metrics, documented dataset limitations) as
first-class design goals.
