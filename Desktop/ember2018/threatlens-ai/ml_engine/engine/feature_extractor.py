import sys
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from ember.features import PEFeatureExtractor

# Initialize the official EMBER feature extractor
extractor = PEFeatureExtractor(feature_version=2)


def extract_features(file_path):
    """
    Extract the official EMBER feature vector (2381 features)
    from a Windows executable.
    """

    # Read the executable as raw bytes
    with open(file_path, "rb") as f:
        bytez = f.read()

    # Extract raw feature dictionary
    raw_features = extractor.raw_features(bytez)

    # Convert to 2381-dimensional feature vector
    feature_vector = extractor.process_raw_features(raw_features)

    return feature_vector
