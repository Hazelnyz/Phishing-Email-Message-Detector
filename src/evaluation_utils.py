"""Metrics and privacy-safe evaluation helpers."""
import re
import numpy as np
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score

def evaluate(y_true, scores, threshold=0.5):
    pred = (np.asarray(scores) >= threshold).astype(int)
    out = {"size": int(len(pred)), "accuracy": float(accuracy_score(y_true, pred)),
           "precision": float(precision_score(y_true, pred, zero_division=0)),
           "recall": float(recall_score(y_true, pred, zero_division=0)),
           "f1": float(f1_score(y_true, pred, zero_division=0)),
           "confusion_matrix": confusion_matrix(y_true, pred, labels=[0,1]).tolist()}
    try: out["roc_auc"] = float(roc_auc_score(y_true, scores))
    except ValueError: out["roc_auc"] = None
    return out, pred

def mask_text(text):
    text = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "[EMAIL]", str(text))
    text = re.sub(r"(?<!\w)(?:\+?\d[\d ()-]{7,}\d)(?!\w)", "[PHONE]", text)
    return text[:500]

def select_threshold(y, scores):
    # Validation only; maximize F1, favoring recall on ties.
    options = [i / 100 for i in range(10, 91)]
    return max(options, key=lambda t: (f1_score(y, np.asarray(scores) >= t, zero_division=0),
                                       recall_score(y, np.asarray(scores) >= t, zero_division=0)))
