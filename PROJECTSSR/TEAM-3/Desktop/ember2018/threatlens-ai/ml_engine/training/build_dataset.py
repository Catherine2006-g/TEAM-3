import json
import numpy as np
from tqdm import tqdm
from sklearn.feature_extraction import FeatureHasher

# Official EMBER feature extractor
from ember.features import PEFeatureExtractor

# Compatibility shim for newer scikit-learn versions
_original_transform = FeatureHasher.transform


def _compat_transform(self, X):
    if isinstance(X, (list, tuple)) and X and isinstance(X[0], str):
        X = [[value] for value in X]
    return _original_transform(self, X)


FeatureHasher.transform = _compat_transform

INPUT_FILE = "labeled_train.jsonl"

extractor = PEFeatureExtractor(feature_version=2)

X = []
y = []

print("Reading dataset...")

with open(INPUT_FILE, "r", encoding="utf-8") as f:
    for line in tqdm(f):
        record = json.loads(line)

        # Convert raw JSON features into a 2381-dimensional vector
        features = extractor.process_raw_features(record)

        X.append(features)
        y.append(record["label"])

X = np.array(X, dtype=np.float32)
y = np.array(y, dtype=np.int8)

print("\nFinished!")

print("Feature matrix shape :", X.shape)
print("Label vector shape   :", y.shape)

np.save("X_train.npy", X)
np.save("y_train.npy", y)

print("\nSaved:")
print("X_train.npy")
print("y_train.npy")
