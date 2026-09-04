import numpy as np
import matplotlib.pyplot as plt
import lightgbm as lgb

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    confusion_matrix,
    classification_report,
    ConfusionMatrixDisplay,
    RocCurveDisplay,
    roc_auc_score,
)

print("=" * 60)
print("Loading Dataset")
print("=" * 60)

X = np.load("X_train.npy", mmap_mode="r")
y = np.load("y_train.npy", mmap_mode="r")

# -----------------------------------------------------
# IMPORTANT
# Use the SAME balanced subset used during training
# -----------------------------------------------------

SAMPLES = 50000

pos_idx = np.flatnonzero(y == 1)
neg_idx = np.flatnonzero(y == 0)

n_pos = min(SAMPLES // 2, len(pos_idx))
n_neg = min(SAMPLES // 2, len(neg_idx))

rng = np.random.RandomState(42)
selected_pos = rng.choice(pos_idx, size=n_pos, replace=False)
selected_neg = rng.choice(neg_idx, size=n_neg, replace=False)
indices = np.concatenate([selected_pos, selected_neg])
rng.shuffle(indices)

X_small = np.ascontiguousarray(X[indices], dtype=np.float32)
y_small = y[indices].astype(np.int8)

# -----------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X_small,
    y_small,
    test_size=0.2,
    random_state=42,
    stratify=y_small,
)

print("Training a fresh LightGBM model for evaluation...")

model = lgb.LGBMClassifier(
    objective="binary",
    n_estimators=100,
    learning_rate=0.1,
    num_leaves=31,
    random_state=42,
    n_jobs=2,
)

model.fit(X_train, y_train)

print("Predicting...")

X_test_eval = np.ascontiguousarray(X_test, dtype=np.float32)
pred = model.predict(X_test_eval)
prob = model.predict_proba(X_test_eval)[:, 1]

print("\nClassification Report\n")
print(classification_report(y_test, pred))

cm = confusion_matrix(y_test, pred)

disp = ConfusionMatrixDisplay(cm)

disp.plot()

plt.title("Confusion Matrix")

plt.savefig("confusion_matrix.png", dpi=300)

plt.close()

RocCurveDisplay.from_predictions(y_test, prob)

plt.title("ROC Curve")

plt.savefig("roc_curve.png", dpi=300)

plt.close()

print("\nROC AUC :", roc_auc_score(y_test, prob))

print("\nEvaluation completed.")

print("\nSaved:")

print("confusion_matrix.png")

print("roc_curve.png")
