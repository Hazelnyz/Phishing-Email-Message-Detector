"""Build a documentation report from saved, measured evaluation artifacts."""
import json
import os
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(ROOT, "evaluation", "metrics.json"), encoding="utf-8") as f:
    m = json.load(f)
errors = pd.read_csv(os.path.join(ROOT, "evaluation", "errors.csv")).fillna("")
lines = ["# Evaluation results", "", "Generated from saved evaluation data. Measurements are not production performance estimates.", "", "## Dataset counts", "", "| Split | Rows | Legitimate | Phishing |", "|---|---:|---:|---:|"]
split_labels = {"train": "Training", "validation": "Validation", "template_family_held_out": "Template-family held-out", "hard_test": "Handwritten hard test"}
for split, name in split_labels.items():
    lines.append(f"| {name} | {m['split_counts'][split]} | {m['split_class_counts'][split].get('legitimate', 0)} | {m['split_class_counts'][split].get('phishing', 0)} |")
lines += ["", "## Metrics by model and test set", "", "| Model | Test set | N | Accuracy | Precision | Recall | F1 | ROC-AUC |", "|---|---|---:|---:|---:|---:|---:|---:|"]
for test_set, models in m["test_sets"].items():
    for model, r in models.items():
        lines.append(f"| {model} | {test_set.replace('_', ' ')} | {r['size']} | {r['accuracy']:.4f} | {r['precision']:.4f} | {r['recall']:.4f} | {r['f1']:.4f} | {r['roc_auc']:.4f} |")
lines += ["", "## Confusion matrices", "", "Order: actual rows and predicted columns are legitimate, phishing.", ""]
for test_set, models in m["test_sets"].items():
    lines += [f"### {test_set.replace('_', ' ').title()}", "", "| Model | Actual | Legitimate | Phishing |", "|---|---|---:|---:|"]
    for model, r in models.items():
        cm = r["confusion_matrix"]
        lines.append(f"| {model} | Legitimate | {cm[0][0]} | {cm[0][1]} |")
        lines.append(f"| {model} | Phishing | {cm[1][0]} | {cm[1][1]} |")
    lines.append("")
lines += ["## Grouped cross-validation", "", "Five folds grouped by template family; values are fold mean and standard deviation.", "", "| Model | Measure | Mean | Std. dev. |", "|---|---|---:|---:|"]
for model, measures in m["cross_validation"].items():
    for metric, r in measures.items():
        lines.append(f"| {model} | {metric} | {r['mean']:.4f} | {r['std']:.4f} |")
lines += ["", "## Model and threshold selection", "", f"Selected **{m['best_model']}** by validation F1 with phishing recall prioritised (minimum target recall 0.90). Threshold: **{m['threshold']:.6f}**. The hard test was not used for selection.", "", "## Misclassified messages", ""]
fp = errors[(errors.true_label == "legitimate") & (errors.predicted_label == "phishing")]
fn = errors[(errors.true_label == "phishing") & (errors.predicted_label == "legitimate")].drop_duplicates("message")
lines += [f"Observed false positives across evaluated sets and models: **{len(fp)}**. No examples are fabricated when none were observed.", "", "### False negatives (up to 10 recorded examples)", "", "| Message | Recorded reason |", "|---|---|"]
for _, r in fn.head(10).iterrows():
    message = str(r.message).replace("|", "\\|").replace("\n", " ")
    reason = f"{r.model}, {r.test_set.replace('_', ' ')}: predicted legitimate at phishing probability {float(r.score):.4f}; signals: {r.top_signals or 'none recorded'}."
    lines.append(f"| {message} | {reason} |")
lines += ["", "## Complete signal detail", "", "- Urgency / Time Pressure: weight 15.", "- Threats / Negative Consequences: weight 20.", "- Credential / OTP Request: weight 30; password/PWD, OTP, PIN, CVV/CVC, credit/debit card details or number, expiry, bank/account/acct details or number, UPI, IFSC, net-banking login, Aadhaar/Aadhar, PAN, passport, date of birth/DOB, registration number. Informal variants include ur/u, gimme, pls/plz, acct, no., info, pwd, otp, cvv.", "- Suspicious Payment / Financial Request: weight 20.", "- Suspicious URL: weight 10 or 25 by severity; checks shorteners, IP hosts, long subdomain chains, lookalike/trusted-domain mismatch, uncommon TLDs, and HTTP.", "- Link Present: weight 5 when a link has no other URL issue.", "- Sender / Domain Mismatch: weight 20 when sender information is supplied.", "", "## Scoring formula", "", "ML contribution = phishing probability x 50 (0-50 points). Rule contribution = sum of signal weights, capped at 50. Total is the sum clamped to 0-100. LOW is below 35, MEDIUM is 35-64, HIGH is 65 or higher. Any high/critical signal imposes a MEDIUM minimum. Unsignalled messages shorter than five words return INSUFFICIENT INFORMATION.", "", "## Known limitations", "", "- Training and generated held-out data are synthetic; family holdout does not make them representative.", "- The hand-written hard test is small and manually labeled; it cannot establish deployment performance.", "- Reported metrics describe text classifiers at the selected validation threshold, not the combined rule-plus-ML risk label.", "- Sender mismatch uses a limited trusted-domain list. Rules and models may miss new wording, context, or languages.", "- Results are flags for human review. URLs are parsed locally and never fetched/opened; messages are not stored.", ""]
os.makedirs(os.path.join(ROOT, "docs"), exist_ok=True)
with open(os.path.join(ROOT, "docs", "RESULTS_SUMMARY.md"), "w", encoding="utf-8") as f:
    f.write("\n".join(lines))
