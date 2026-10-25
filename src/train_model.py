"""Train candidates, select using validation only, then score held-out sets."""
import json
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, roc_auc_score, make_scorer)
from sklearn.model_selection import GroupKFold, cross_validate
from sklearn.pipeline import Pipeline
from signal_detector import detect_signals

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA, MODELS, EVAL = (os.path.join(ROOT, p) for p in ("data", "models", "evaluation"))
os.makedirs(MODELS, exist_ok=True)
os.makedirs(EVAL, exist_ok=True)
LABELS = ["legitimate", "phishing"]

def load(filename):
    return pd.read_csv(os.path.join(DATA, filename))

def make_pipeline(estimator):
    return Pipeline([("tfidf", TfidfVectorizer(lowercase=True, stop_words="english",
        ngram_range=(1, 2), max_features=5000)), ("model", estimator)])

def score_rows(actual, predicted, probability):
    return {
        "accuracy": float(accuracy_score(actual, predicted)),
        "precision": float(precision_score(actual, predicted, pos_label="phishing", zero_division=0)),
        "recall": float(recall_score(actual, predicted, pos_label="phishing", zero_division=0)),
        "f1": float(f1_score(actual, predicted, pos_label="phishing", zero_division=0)),
        "roc_auc": float(roc_auc_score((pd.Series(actual) == "phishing").astype(int), probability)),
        "confusion_matrix": confusion_matrix(actual, predicted, labels=LABELS).tolist(),
        "confusion_matrix_labels": LABELS,
    }

def main():
    # Only training and validation data are read before the selected model and
    # threshold are fixed. The hard test is not available to selection logic.
    train, validation = load("train.csv"), load("validation.csv")
    candidates = {
        "Multinomial Naive Bayes": make_pipeline(MultinomialNB()),
        "Logistic Regression": make_pipeline(LogisticRegression(max_iter=1500, random_state=42)),
    }
    candidate_results, cv_results = {}, {}
    scorers = {
        "precision": make_scorer(precision_score, pos_label="phishing", zero_division=0),
        "recall": make_scorer(recall_score, pos_label="phishing", zero_division=0),
        "f1": make_scorer(f1_score, pos_label="phishing", zero_division=0),
    }
    folds = GroupKFold(n_splits=min(5, train.family.nunique()))

    for name, model in candidates.items():
        model.fit(train.message, train.label)
        classes = list(model.classes_)
        validation_prob = model.predict_proba(validation.message)[:, classes.index("phishing")]
        threshold_values = sorted(set([0.25, 0.35, 0.5, 0.65, *validation_prob.tolist()]))
        threshold_rows = []
        for threshold in threshold_values:
            predicted = np.where(validation_prob >= threshold, "phishing", "legitimate")
            threshold_rows.append({"threshold": float(threshold),
                                   **score_rows(validation.label, predicted, validation_prob)})
        eligible = [row for row in threshold_rows if row["recall"] >= 0.90] or threshold_rows
        chosen_validation = max(eligible, key=lambda row: (row["f1"], row["recall"]))
        cv = cross_validate(model, train.message, train.label, groups=train.family,
                            cv=folds, scoring=scorers, return_train_score=False)
        cv_results[name] = {metric: {"mean": float(np.mean(cv[f"test_{metric}"])),
                                     "std": float(np.std(cv[f"test_{metric}"]))}
                            for metric in scorers}
        candidate_results[name] = {"model": model, "validation": chosen_validation,
                                   "validation_thresholds": threshold_rows}

    best_name = max(candidate_results,
                    key=lambda name: (candidate_results[name]["validation"]["f1"],
                                      candidate_results[name]["validation"]["recall"]))
    best_candidate = candidate_results[best_name]
    threshold = best_candidate["validation"]["threshold"]

    # Only now load held-out data, after model and threshold selection.
    test_sets = {
        "template_family_held_out": load("test.csv"),
        "hard_test": load("hard_test.csv"),
    }
    results, errors = [], []
    for name, candidate in candidate_results.items():
        model = candidate["model"]
        set_results = {}
        for set_name, frame in test_sets.items():
            probabilities = model.predict_proba(frame.message)[:, list(model.classes_).index("phishing")]
            predicted = np.where(probabilities >= candidate["validation"]["threshold"], "phishing", "legitimate")
            result = score_rows(frame.label, predicted, probabilities)
            result["size"] = len(frame)
            set_results[set_name] = result
            for row, actual, guess, probability in zip(frame.to_dict("records"), frame.label,
                                                        predicted, probabilities):
                if actual != guess:
                    signals = detect_signals(row["message"])["signals"]
                    top_signals = "; ".join(s["category"] for s in
                        sorted(signals, key=lambda signal: -signal["weight"])[:3])
                    errors.append({"message": row["message"], "true_label": actual,
                        "predicted_label": guess, "score": float(probability),
                        "top_signals": top_signals, "model": name, "test_set": set_name})
        family_result = set_results["template_family_held_out"]
        results.append({"model": name, **family_result,
            "precision_phishing": family_result["precision"],
            "recall_phishing": family_result["recall"], "f1_phishing": family_result["f1"],
            "test_sets": set_results, "validation": candidate["validation"],
            "validation_thresholds": candidate["validation_thresholds"]})

    best_model = best_candidate["model"]
    joblib.dump(best_model.named_steps["tfidf"], os.path.join(MODELS, "tfidf_vectorizer.joblib"))
    joblib.dump(candidates["Multinomial Naive Bayes"].named_steps["model"],
                os.path.join(MODELS, "naive_bayes_model.joblib"))
    joblib.dump(candidates["Logistic Regression"].named_steps["model"],
                os.path.join(MODELS, "logistic_regression_model.joblib"))
    joblib.dump(best_model.named_steps["model"], os.path.join(MODELS, "best_model.joblib"))
    with open(os.path.join(MODELS, "best_model_info.json"), "w", encoding="utf-8") as stream:
        json.dump({"best_model_name": best_name, "threshold": threshold}, stream, indent=2)

    split_frames = {"train": train, "validation": validation, **test_sets}
    metrics = {
        "train_size": len(train), "test_size": len(test_sets["template_family_held_out"]),
        "split_counts": {key: len(frame) for key, frame in split_frames.items()},
        "split_class_counts": {key: {str(label): int(count) for label, count in
                                      frame.label.value_counts().items()}
                               for key, frame in split_frames.items()},
        "best_model": best_name, "threshold": threshold,
        "threshold_selection": "validation F1 with phishing recall prioritised (target recall >= 0.90)",
        "results": results, "cross_validation": cv_results,
        "test_sets": {key: {row["model"]: row["test_sets"][key] for row in results}
                      for key in test_sets},
    }
    with open(os.path.join(EVAL, "metrics.json"), "w", encoding="utf-8") as stream:
        json.dump(metrics, stream, indent=2)
    pd.DataFrame(errors, columns=["message", "true_label", "predicted_label", "score",
                                 "top_signals", "model", "test_set"]).to_csv(
        os.path.join(EVAL, "errors.csv"), index=False)
    print(f"Selected {best_name} at validation threshold {threshold:.6f}")

if __name__ == "__main__":
    main()
