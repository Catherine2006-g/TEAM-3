import joblib
import numpy as np
from pathlib import Path


class Predictor:
    def __init__(self):
        model_path = Path(__file__).resolve().parent.parent / "model" / "lightgbm_model_v1.0.pkl"
        self.model = joblib.load(model_path)

    def predict(self, feature_vector):
        feature_vector = np.asarray(feature_vector, dtype=np.float32).reshape(1, -1)

        prediction = int(self.model.predict(feature_vector)[0])
        probability = float(self.model.predict_proba(feature_vector)[0][1])

        return prediction, probability
