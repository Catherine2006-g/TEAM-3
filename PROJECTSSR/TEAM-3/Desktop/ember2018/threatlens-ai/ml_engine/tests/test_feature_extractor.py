from scanner.feature_extractor import extract_features

# Replace this with any Windows executable
file_path = "sample.exe"

features = extract_features(file_path)

print("Feature vector length:", len(features))

print("\nFirst 20 features:")

print(features[:20])
