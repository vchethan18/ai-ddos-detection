import pandas as pd
from sklearn.ensemble           import RandomForestClassifier
from sklearn.model_selection    import train_test_split
from sklearn.metrics            import accuracy_score, confusion_matrix, classification_report
import matplotlib.pyplot        as plt
import joblib
import os

# ── Paths ────────────────────────────────────────────────────────────
CSV_PATH   = "data/network_data_multiclass.csv"
MODEL_PATH = "models/random_forest_multiclass.pkl"

# ── Label names ──────────────────────────────────────────────────────
LABEL_MAP = {
    0: "Normal",
    1: "SYN Flood",
    2: "UDP Flood",
    3: "ICMP Flood",
    4: "Port Scan",
    5: "TCP ACK Flood",
    6: "TCP RST Flood",
    7: "DNS Flood",
    8: "ARP Flood"
}

# ── Features used for training ───────────────────────────────────────
FEATURES = [
    "pps", "bytes",
    "tcp", "udp", "icmp",
    "tcp_ratio", "udp_ratio",
    "unique_ips", "unique_ports",
    "syn", "ack", "rst", "fin",
    "top_port"
]
TARGET = "label"


# ── 1. Load dataset ──────────────────────────────────────────────────
print("[1] Loading dataset...")
df = pd.read_csv(CSV_PATH)

print(f"    Total rows : {len(df)}")
for label_num in sorted(df[TARGET].unique()):
    name  = LABEL_MAP.get(label_num, f"Unknown({label_num})")
    count = (df[TARGET] == label_num).sum()
    print(f"    {name:<12} ({label_num}) : {count}")

if df[TARGET].nunique() < 2:
    print("\n[!] Dataset has only one class — collect more traffic types first.")
    exit()

missing = set(LABEL_MAP.keys()) - set(df[TARGET].unique())
if missing:
    missing_names = [LABEL_MAP[m] for m in missing]
    print(f"\n[!] Warning: no data for {missing_names} — model won't be able to detect these.")


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

accuracy       = accuracy_score(y_test, y_pred)
labels_present = sorted(y.unique())
names_present  = [LABEL_MAP.get(l, str(l)) for l in labels_present]
cm             = confusion_matrix(y_test, y_pred, labels=labels_present)

print(f"\n    Accuracy : {accuracy * 100:.2f}%")

print("\n    Confusion Matrix (rows = actual, columns = predicted):")
col_header = "    " + " " * 14 + "".join(f"{n:<12}" for n in names_present)
print(col_header)
for i, row_label in enumerate(names_present):
    row_vals = "".join(f"{cm[i][j]:<12}" for j in range(len(names_present)))
    print(f"    {row_label:<14}{row_vals}")

print("\n    Classification Report:")
print(classification_report(y_test, y_pred, labels=labels_present, target_names=names_present))


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
plt.title("Feature Importance — Random Forest (Multi-Class)")
plt.ylabel("Importance Score")
plt.tight_layout()
plt.savefig("models/feature_importance_multiclass.png")
print("\n    Plot saved → models/feature_importance_multiclass.png")


# ── 6. Save model ─────────────────────────────────────────────────────
print("\n[6] Saving model...")
os.makedirs("models", exist_ok=True)
joblib.dump(model, MODEL_PATH)
print(f"    Model saved → {MODEL_PATH}")
