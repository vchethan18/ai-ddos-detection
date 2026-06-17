import pandas as pd
from sklearn.ensemble           import RandomForestClassifier
from sklearn.model_selection    import train_test_split
from sklearn.metrics            import accuracy_score, confusion_matrix, classification_report
import matplotlib.pyplot        as plt
import joblib
import os

# ── Paths ────────────────────────────────────────────────────────────
CSV_PATH   = "data/network_data_v3.csv"
MODEL_PATH = "models/random_forest.pkl"

# ── Features used for training ───────────────────────────────────────
FEATURES = [
    "pps", "bytes",
    "tcp", "udp", "tcp_ratio", "udp_ratio",
    "unique_ips", "unique_ports",
    "ack", "rst", "fin",
    "top_port"
]
TARGET = "label"


# ── 1. Load dataset ──────────────────────────────────────────────────
print("[1] Loading dataset...")
df = pd.read_csv(CSV_PATH)

print(f"    Total rows  : {len(df)}")
print(f"    Normal  (0) : {(df[TARGET] == 0).sum()}")
print(f"    Attack  (1) : {(df[TARGET] == 1).sum()}")

if df[TARGET].nunique() < 2:
    print("\n[!] Dataset has only one class — collect attack traffic first.")
    exit()


# ── 2. Split ─────────────────────────────────────────────────────────
print("\n[2] Splitting 80/20...")
X = df[FEATURES]
y = df[TARGET]

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size    = 0.2,
    random_state = 42,
    stratify     = y          # keeps class balance in both splits
)

print(f"    Train rows : {len(X_train)}")
print(f"    Test rows  : {len(X_test)}")


# ── 3. Train ─────────────────────────────────────────────────────────
print("\n[3] Training Random Forest...")
model = RandomForestClassifier(
    n_estimators = 100,
    random_state = 42,
    n_jobs       = -1,
    class_weight  = 'balanced'
)
model.fit(X_train, y_train)
print("    Done.")


# ── 4. Evaluate ──────────────────────────────────────────────────────
print("\n[4] Evaluating...")
y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
cm       = confusion_matrix(y_test, y_pred)

print(f"\n    Accuracy : {accuracy * 100:.2f}%")

print("\n    Confusion Matrix:")
print(f"                 Predicted")
print(f"                 Normal  Attack")
print(f"    Actual Normal  {cm[0][0]:<6}  {cm[0][1]}")
print(f"    Actual Attack  {cm[1][0]:<6}  {cm[1][1]}")

print("\n    Classification Report:")
print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"]))


# ── 5. Feature importance ─────────────────────────────────────────────
print("\n[5] Feature Importance:")
importances = pd.Series(model.feature_importances_, index=FEATURES)
importances = importances.sort_values(ascending=False)

for feat, score in importances.items():
    bar = "█" * int(score * 50)
    print(f"    {feat:<15} {score:.4f}  {bar}")

# save plot
plt.figure(figsize=(10, 6))
importances.plot(kind="bar")
plt.title("Feature Importance — Random Forest")
plt.ylabel("Importance Score")
plt.tight_layout()
plt.savefig("models/feature_importance.png")
print("\n    Plot saved → models/feature_importance.png")


# ── 6. Save model ─────────────────────────────────────────────────────
print("\n[6] Saving model...")
os.makedirs("models", exist_ok=True)
joblib.dump(model, MODEL_PATH)
print(f"    Model saved → {MODEL_PATH}")
