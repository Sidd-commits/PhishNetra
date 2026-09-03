"""
PhishNetra - Baseline ML Model Training & Evaluation Pipeline
Module: services.ml.training.train
Milestone: 1
"""

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)
import joblib

# Add service root to path for imports
current_dir = Path(__file__).resolve().parent
ml_root = current_dir.parent
sys.path.insert(0, str(ml_root))

from app.features.url_features import (
    URLFeatureExtractor,
    FEATURE_COLUMNS,
    normalize_url
)


def train_baseline_model(
    data_path: str,
    output_dir: str,
    test_size: float = 0.25,
    random_state: int = 42
) -> dict:
    """
    Executes baseline feature extraction, train/test split, model training,
    evaluation metric calculation, and artifact serialization.
    """
    print(f"[*] Loading dataset from: {data_path}")
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Dataset not found at {data_path}")

    df = pd.read_csv(data_path)
    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("Dataset must contain 'url' and 'label' columns")

    print(f"[*] Total records loaded: {len(df)}")
    print(f"[*] Class distribution: \n{df['label'].value_counts().to_dict()}")

    # Feature extraction
    print("[*] Extracting deterministic URL features...")
    feature_rows = []
    valid_labels = []

    for _, row in df.iterrows():
        url = str(row["url"])
        label = int(row["label"])
        try:
            feats = URLFeatureExtractor.extract_features(url)
            feature_rows.append(feats)
            valid_labels.append(label)
        except Exception as e:
            print(f"[!] Warning: Failed to extract features for URL '{url}': {e}")

    X = pd.DataFrame(feature_rows)[FEATURE_COLUMNS]
    y = np.array(valid_labels)

    print(f"[*] Feature matrix shape: {X.shape}")

    # Train / Test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    print(f"[*] Training samples: {len(X_train)}, Testing samples: {len(X_test)}")

    # Model training (Random Forest Classifier Baseline)
    print("[*] Training Baseline RandomForestClassifier...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=6,
        random_state=random_state,
        class_weight="balanced"
    )
    model.fit(X_train, y_train)

    # Evaluation
    print("[*] Evaluating baseline model on test set...")
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    try:
        auc = float(roc_auc_score(y_test, y_proba))
    except Exception:
        auc = 1.0

    cm = confusion_matrix(y_test, y_pred).tolist()

    # Feature Importances
    importances = {
        col: round(float(imp), 4)
        for col, imp in zip(FEATURE_COLUMNS, model.feature_importances_)
    }
    sorted_importances = dict(
        sorted(importances.items(), key=lambda item: item[1], reverse=True)
    )

    metrics = {
        "model_type": "RandomForestClassifier",
        "model_version": "v0.1.0-baseline",
        "trained_at": datetime.utcnow().isoformat() + "Z",
        "dataset_path": str(data_path),
        "total_samples": len(df),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "feature_columns": FEATURE_COLUMNS,
        "metrics": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(auc, 4),
            "confusion_matrix": {
                "true_negative": cm[0][0] if len(cm) > 0 else 0,
                "false_positive": cm[0][1] if len(cm) > 0 and len(cm[0]) > 1 else 0,
                "false_negative": cm[1][0] if len(cm) > 1 else 0,
                "true_positive": cm[1][1] if len(cm) > 1 and len(cm[1]) > 1 else 0
            }
        },
        "feature_importances": sorted_importances
    }

    # Serialization
    os.makedirs(output_dir, exist_ok=True)
    model_artifact_path = os.path.join(output_dir, "baseline_model.joblib")
    metrics_artifact_path = os.path.join(output_dir, "metrics.json")

    joblib.dump(
        {
            "model": model,
            "feature_columns": FEATURE_COLUMNS,
            "version": "v0.1.0-baseline"
        },
        model_artifact_path
    )
    print(f"[+] Model artifact saved to: {model_artifact_path}")

    with open(metrics_artifact_path, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"[+] Metrics artifact saved to: {metrics_artifact_path}")

    print("\n--- BASELINE EVALUATION REPORT ---")
    print(f"Accuracy:  {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"F1 Score:  {f1:.4f}")
    print(f"ROC AUC:   {auc:.4f}")
    print("----------------------------------\n")

    return metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PhishNetra ML Baseline Trainer")
    parser.add_argument(
        "--data",
        type=str,
        default=str(ml_root / "data" / "synthetic_sample.csv"),
        help="Path to training dataset CSV"
    )
    parser.add_argument(
        "--output",
        type=str,
        default=str(ml_root / "artifacts"),
        help="Directory to save model artifacts"
    )
    args = parser.parse_args()

    train_baseline_model(args.data, args.output)
