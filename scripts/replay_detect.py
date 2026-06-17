#!/usr/bin/env python3
"""
replay_detect.py
Validates the trained Random Forest model against the existing labeled
dataset (network_data.csv) before moving to live packet capture.
"""

import pandas as pd
import joblib
import sys

MODEL_PATH = "models/random_forest.pkl"
DATA_PATH = "data/network_data_v3.csv"

# Exact feature order the model was trained on
FEATURE_COLS = ['pps', 'bytes', 'tcp', 'udp', 'tcp_ratio', 'udp_ratio',
                'unique_ips', 'unique_ports', 'ack', 'rst', 'fin', 'top_port']

def main():
    print(f"[1] Loading model from {MODEL_PATH} ...")
    model = joblib.load(MODEL_PATH)

    print(f"[2] Loading dataset from {DATA_PATH} ...")
    df = pd.read_csv(DATA_PATH)

    missing = [c for c in FEATURE_COLS + ["label"] if c not in df.columns]
    if missing:
        print(f"ERROR: dataset missing expected columns: {missing}")
        sys.exit(1)

    X = df[FEATURE_COLS]
    y_true = df["label"]

    print(f"[3] Running predictions on {len(df)} rows ...")
    y_pred = model.predict(X)
    proba = model.predict_proba(X)
    confidences = proba.max(axis=1)

    df["predicted"] = y_pred
    df["confidence"] = confidences
    df["correct"] = df["predicted"] == y_true

    total = len(df)
    correct = int(df["correct"].sum())
    accuracy = correct / total * 100

    print(f"\n[4] Results: {correct}/{total} correct  ({accuracy:.2f}% accuracy)\n")

    mismatches = df[~df["correct"]]
    if len(mismatches) == 0:
        print("No mismatches — every row predicted correctly.")
    else:
        print(f"Mismatches ({len(mismatches)} rows):")
        print(f"{'row':>5} {'timestamp':<22} {'actual':<8} {'predicted':<10} {'confidence':<10}")
        for idx, row in mismatches.iterrows():
            print(f"{idx:>5} {str(row['timestamp']):<22} {row['label']:<8} "
                  f"{row['predicted']:<10} {row['confidence']:.2f}")

    tp = int(((df['predicted'] == 1) & (y_true == 1)).sum())
    tn = int(((df['predicted'] == 0) & (y_true == 0)).sum())
    fp = int(((df['predicted'] == 1) & (y_true == 0)).sum())
    fn = int(((df['predicted'] == 0) & (y_true == 1)).sum())

    print("\n[5] Confusion Matrix:")
    print("                 Predicted")
    print("                 Normal  Attack")
    print(f"    Actual Normal  {tn:<6}  {fp:<6}")
    print(f"    Actual Attack  {fn:<6}  {tp:<6}")

if __name__ == "__main__":
    main()
