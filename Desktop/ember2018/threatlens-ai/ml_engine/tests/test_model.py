import sys
from pathlib import Path
import joblib

model_path = Path(__file__).resolve().parent.parent / "model" / "lightgbm_model_v1.0.pkl"
print(f"Loading model from {model_path.name}...")

model = joblib.load(str(model_path))

print("Model loaded successfully!")
print(model)

