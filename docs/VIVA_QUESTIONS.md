# Viva Questions and Answers — PhishGuard AI

### Q1. What problem does PhishGuard AI solve?
It analyses a free-text message (such as an SMS, email, or chat message) and
estimates whether it is a phishing attempt, giving a risk level (HIGH /
MEDIUM / LOW RISK or INSUFFICIENT INFORMATION), an explanation, and safe
recommended actions — rather than just a bare yes/no label.

### Q2. Why combine a machine learning model with rule-based detection instead of using just one?
The ML model (TF-IDF + Logistic Regression/Naive Bayes) captures statistical
language patterns learned from training data, but it's a black box and can be
wrong on text unlike anything in its training set. The rule-based detector is
fully explainable and catches specific known phishing tactics (urgency,
threats, credential requests, suspicious URLs) even if the ML model is
uncertain. Combining both gives more robust, explainable results than either
alone, and means the system degrades more gracefully for messages that don't
closely resemble the training data.

### Q3. How was the dataset built, and why is it synthetic?
`src/generate_dataset.py` programmatically combines hand-written message
templates (phishing and legitimate categories) with randomised names, fake
domains, and fake amounts to generate 600 labelled messages. It's synthetic
for safety and ethics (no real student data or real phishing content is
used), reproducibility (seeded random generation), and labelling confidence
(every label is correct by construction). See `DATASET_README.md`.

### Q4. How do you prevent data leakage between training and test sets?
Complete template families are separated into training, validation, and the
family-held-out test split before vectorization. The TF-IDF vectorizer is fit
only on training messages. The handwritten hard test is never used for
training, model selection, or threshold selection. Tests assert family
separation and that hard-test messages do not appear in generated data.

### Q5. Which models were trained and how was the best one selected?
Multinomial Naive Bayes and Logistic Regression use the same TF-IDF approach.
Model and threshold selection use validation F1 with phishing recall
prioritised. The chosen model is saved as `models/best_model.joblib`.
Current metrics and model selection are reported in `RESULTS_SUMMARY.md`,
generated from `evaluation/metrics.json`.

### Q6. Why F1-score (and specifically on the phishing class) as the selection metric, rather than accuracy?
In phishing detection, false negatives (missing a real phishing message) and
false positives (flagging a safe message) have different costs, and the
classes can be imbalanced in real deployments even if this demo dataset is
balanced. F1-score balances precision and recall, and focusing on the
phishing class specifically keeps the metric centered on the harmful class
we most need to catch.

### Q7. Do high evaluation scores mean the model is perfect?
No. The generated data is synthetic and uses authored templates, so its
language may be easier to classify than arbitrary real messages. The
handwritten hard-test results and model errors in `RESULTS_SUMMARY.md` provide
additional checks, but the hard test is small and does not establish
real-world performance.

### Q8. How is the final risk score computed?
`src/risk_engine.py` combines two components into a 0–100 score: the ML
model's predicted phishing probability contributes up to 50 points
(`probability × 50`), and the rule-based signal detector's total weight
(urgency, threats, credential requests, suspicious URLs, sender mismatch,
payment requests) contributes up to 50 points (capped). The combined score
maps to HIGH RISK (≥65), MEDIUM RISK (35–64), or LOW RISK (<35).

### Q9. What counts as INSUFFICIENT INFORMATION, and why have that category at all?
Any message under five words with no detected signals. It exists so the tool doesn't force a
confident-sounding risk label onto text that's too short to meaningfully
analyse (e.g. "hi"), which would otherwise mislead the user.

### Q10. What phishing signals does the rule-based detector look for?
Signals cover urgency/time pressure, threats, sensitive-information and
credential requests, suspicious payments, suspicious URLs and ordinary links,
and sender/domain mismatch against configured trusted domains.

### Q11. How are URLs analysed without visiting them?
`src/signal_detector.py::analyze_urls` uses Python's `urllib.parse` to
extract the hostname, scheme, subdomain structure, and TLD from the URL
*string* only. It checks the host against known shortener domains, checks for
IP-literal hosts, counts subdomain depth, checks suspicious TLDs, and computes
a Levenshtein edit-distance against trusted domains to catch lookalikes
(e.g. `vit.ac.in.login-secure.com`). No HTTP request is ever made — this is
verified by a test that intercepts `socket.create_connection` and asserts it
is never called during URL analysis.

### Q12. How do you prevent XSS or other injection from user-submitted messages?
Flask/Jinja2 autoescapes all template variables by default, so any HTML or
JavaScript in a submitted message is rendered as literal escaped text rather
than executed. This is explicitly tested in
`tests/test_flask_routes.py::test_message_is_escaped_in_rendered_html`.

### Q13. Why does the tool explicitly say it will never ask for a password or OTP?
Because a key phishing red flag — and the behaviour phishers exploit — is
asking for credentials. If PhishGuard AI itself requested a password/OTP for
"verification," it would both model and legitimise exactly the behaviour it's
trying to teach users to distrust. The UI, forms, and backend never collect
or store credential-like fields.

### Q14. What does "LOW RISK" actually guarantee?
Nothing on its own — it means few or no known phishing indicators were
detected, not that the message is certainly safe. Every LOW RISK result's
explanation includes this caveat, and the About/Awareness pages repeat it.

### Q15. How would you extend this project for production use?
A much larger and more linguistically diverse, human-verified dataset;
periodic retraining on newly confirmed phishing samples; real sender
authentication (SPF/DKIM) where headers are available; multilingual support;
an email client or browser-extension front-end; rate-limiting and
authentication on the API; and ongoing evaluation against novel/adversarial
phishing techniques, since phishing tactics evolve faster than a static
model.

### Q16. What testing was done, and what does it verify?
42 pytest tests across four files: signal-detector correctness (including a
no-network-access guarantee for URL analysis), risk-engine behaviour and
score bounds, dataset/model integrity (including the train/test leakage
check), and Flask route behaviour (including the XSS-escaping test and the
JSON API). All tests passed in the most recent run.

### Q17. Why Flask rather than a heavier framework?
Flask is lightweight, has minimal boilerplate for a small number of routes,
integrates cleanly with Jinja2 templating and a Python ML stack
(scikit-learn, pandas, joblib), and is well-suited to a project of this scope
and an educational demonstration.

### Q18. What's the difference between the ML model's output and the rule-based signals in the final explanation?
The ML prediction is a single probabilistic label (`phishing`/`legitimate`
with a confidence percentage) learned statistically from text patterns. The
rule-based signals are a list of specific, named, explainable reasons (e.g.
"Credential / OTP Request") with individual severity and weight. The
explanation shown to the user combines both: the model's verdict plus the
concrete evidence behind it.
