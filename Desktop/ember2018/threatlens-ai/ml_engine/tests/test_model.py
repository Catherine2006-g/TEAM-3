import joblib

print("Loading model...")

model = joblib.load("lightgbm_model.pkl")

print("Model loaded successfully!")

print(model)
