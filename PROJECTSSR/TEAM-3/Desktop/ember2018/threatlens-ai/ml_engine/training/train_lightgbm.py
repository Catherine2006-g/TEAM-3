import time
import joblib
import lightgbm as lgb
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
)

print("=" * 60)
print("Loading dataset...")
print("=" * 60)

# Memory-mapped loading
X = np.load("X_train.npy", mmap_mode="r")
y = np.load("y_train.npy", mmap_mode="r")

print("Dataset loaded.")
print("Shape:", X.shape)

# -------------------------------------------------------
# TEMPORARY
# Train on a balanced subset of 50,000 samples
# -------------------------------------------------------

SAMPLES = 50000

pos_idx = np.flatnonzero(y == 1)
neg_idx = np.flatnonzero(y == 0)

if len(pos_idx) == 0 or len(neg_idx) == 0:
    raise ValueError("The label array does not contain both classes.")

n_pos = min(SAMPLES // 2, len(pos_idx))
n_neg = min(SAMPLES // 2, len(neg_idx))

rng = np.random.RandomState(42)
selected_pos = rng.choice(pos_idx, size=n_pos, replace=False)
selected_neg = rng.choice(neg_idx, size=n_neg, replace=False)
sample_idx = np.concatenate([selected_pos, selected_neg])
rng.shuffle(sample_idx)

X_small = X[sample_idx]
y_small = y[sample_idx]

print(f"\nUsing {len(sample_idx):,} balanced samples for the first training run.")

# -------------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X_small,
    y_small,
    test_size=0.2,
    random_state=42,
    stratify=y_small,
)

print("\nTraining samples :", len(X_train))
print("Validation samples:", len(X_test))

model = lgb.LGBMClassifier(
    objective="binary",
    n_estimators=100,
    learning_rate=0.1,
    num_leaves=31,
    random_state=42,
    n_jobs=2,  # Keep RAM usage low
)

print("\nTraining model...")

start = time.time()
model.fit(X_train, y_train)
end = time.time()

print(f"\nTraining completed in {(end - start):.2f} seconds.")

print("\nMaking predictions...")

pred = model.predict(X_test)
prob = model.predict_proba(X_test)[:, 1]

print("\n================ RESULTS ================\n")

print("Accuracy :", accuracy_score(y_test, pred))
print("Precision:", precision_score(y_test, pred, zero_division=0))
print("Recall   :", recall_score(y_test, pred, zero_division=0))
print("F1 Score :", f1_score(y_test, pred, zero_division=0))
print("ROC AUC  :", roc_auc_score(y_test, prob))

joblib.dump(model, "lightgbm_model.pkl")

print("\nModel saved as lightgbm_model.pkl")
