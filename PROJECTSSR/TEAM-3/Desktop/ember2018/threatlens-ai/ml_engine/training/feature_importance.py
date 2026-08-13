import joblib
import matplotlib.pyplot as plt
import numpy as np

print("=" * 60)
print("Loading LightGBM Model")
print("=" * 60)

model = joblib.load("lightgbm_model.pkl")

importance = model.feature_importances_

indices = np.argsort(importance)[::-1]

top_n = 30

plt.figure(figsize=(12, 8))

plt.barh(
    range(top_n),
    importance[indices[:top_n]][::-1],
)

plt.yticks(
    range(top_n),
    [f"Feature {i}" for i in indices[:top_n]][::-1],
)

plt.xlabel("Importance Score")
plt.title("Top 30 Most Important EMBER Features")

plt.tight_layout()

plt.savefig("feature_importance.png", dpi=300)

print("\nSaved:")
print("feature_importance.png")
