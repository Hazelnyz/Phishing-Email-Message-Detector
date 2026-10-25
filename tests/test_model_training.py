"""
Tests for the trained model artifacts and evaluation metrics. These assume
`python src/generate_dataset.py` and `python src/train_model.py` have already
been run (as the project setup instructions direct), producing files in
data/, models/, and evaluation/.
"""

import os
import json
import joblib
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "models")
DATA_DIR = os.path.join(BASE_DIR, "data")
EVAL_DIR = os.path.join(BASE_DIR, "evaluation")


def test_dataset_files_exist():
    assert os.path.exists(os.path.join(DATA_DIR, "train.csv"))
    assert os.path.exists(os.path.join(DATA_DIR, "test.csv"))


def test_train_and_test_sets_do_not_overlap():
    train_df = pd.read_csv(os.path.join(DATA_DIR, "train.csv"))
    test_df = pd.read_csv(os.path.join(DATA_DIR, "test.csv"))
    train_set = set(train_df["message"])
    test_set = set(test_df["message"])
    assert len(train_set & test_set) == 0, "Data leakage: overlapping messages between train and test sets"


def test_template_family_holdout_has_no_family_overlap():
    train_df = pd.read_csv(os.path.join(DATA_DIR, "train.csv"))
    validation_df = pd.read_csv(os.path.join(DATA_DIR, "validation.csv"))
    test_df = pd.read_csv(os.path.join(DATA_DIR, "test.csv"))
    assert set(train_df["family"]).isdisjoint(set(validation_df["family"]))
    assert set(train_df["family"]).isdisjoint(set(test_df["family"]))
    assert set(validation_df["family"]).isdisjoint(set(test_df["family"]))


def test_hard_test_is_hand_authored_and_not_in_generated_data():
    hard = pd.read_csv(os.path.join(DATA_DIR, "hard_test.csv"))
    generated = pd.read_csv(os.path.join(DATA_DIR, "messages_full.csv"))
    assert len(hard) >= 60
    assert set(hard["label"]) == {"phishing", "legitimate"}
    assert set(hard["message"]).isdisjoint(set(generated["message"]))


def test_dataset_has_both_labels():
    train_df = pd.read_csv(os.path.join(DATA_DIR, "train.csv"))
    labels = set(train_df["label"].unique())
    assert labels == {"phishing", "legitimate"}


def test_model_artifacts_exist():
    assert os.path.exists(os.path.join(MODEL_DIR, "tfidf_vectorizer.joblib"))
    assert os.path.exists(os.path.join(MODEL_DIR, "naive_bayes_model.joblib"))
    assert os.path.exists(os.path.join(MODEL_DIR, "logistic_regression_model.joblib"))
    assert os.path.exists(os.path.join(MODEL_DIR, "best_model.joblib"))


def test_vectorizer_and_model_are_compatible():
    vectorizer = joblib.load(os.path.join(MODEL_DIR, "tfidf_vectorizer.joblib"))
    model = joblib.load(os.path.join(MODEL_DIR, "best_model.joblib"))
    X = vectorizer.transform(["This is a test message."])
    pred = model.predict(X)
    assert pred[0] in ("phishing", "legitimate")


def test_metrics_file_has_real_values():
    metrics_path = os.path.join(EVAL_DIR, "metrics.json")
    assert os.path.exists(metrics_path)
    with open(metrics_path) as f:
        metrics = json.load(f)

    assert metrics["train_size"] > 0
    assert metrics["test_size"] > 0
    assert len(metrics["results"]) == 2  # Naive Bayes + Logistic Regression

    for r in metrics["results"]:
        assert 0.0 <= r["accuracy"] <= 1.0
        assert 0.0 <= r["precision_phishing"] <= 1.0
        assert 0.0 <= r["recall_phishing"] <= 1.0
        assert 0.0 <= r["f1_phishing"] <= 1.0
        # Confusion matrix should sum to the test set size
        cm = r["confusion_matrix"]
        total = sum(sum(row) for row in cm)
        assert total == metrics["test_size"]


def test_best_model_selected_by_validation_f1_with_recall_tiebreak():
    metrics_path = os.path.join(EVAL_DIR, "metrics.json")
    with open(metrics_path) as f:
        metrics = json.load(f)
    best_name = metrics["best_model"]
    selected = next(r["validation"] for r in metrics["results"] if r["model"] == best_name)
    assert all((selected["f1"], selected["recall"]) >= (r["validation"]["f1"], r["validation"]["recall"])
               for r in metrics["results"])
