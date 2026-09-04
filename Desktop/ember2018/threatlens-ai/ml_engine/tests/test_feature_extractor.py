import sys
from pathlib import Path

root_dir = Path(__file__).resolve().parent.parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from ml_engine.engine.feature_extractor import extract_features

# Sample file path for testing
file_path = Path(__file__).parent / "sample_test.exe"
if not file_path.exists():
    file_path.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00")

features = extract_features(str(file_path))

print("Feature vector length:", len(features))
print("\nFirst 20 features:")
print(features[:20])

