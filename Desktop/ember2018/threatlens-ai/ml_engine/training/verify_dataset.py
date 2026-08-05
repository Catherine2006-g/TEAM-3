import numpy as np

print("Opening dataset using memory mapping...")

# Memory-mapped loading (does NOT load the whole file into RAM)
X = np.load("X_train.npy", mmap_mode="r")
y = np.load("y_train.npy", mmap_mode="r")

print("\nDataset opened successfully!")

print(f"X shape : {X.shape}")
print(f"y shape : {y.shape}")

print(f"X dtype : {X.dtype}")
print(f"y dtype : {y.dtype}")

print("\nFirst 20 features of first sample:")
print(X[0][:20])

print("\nFirst label:")
print(y[0])

print("\nLabel distribution:")

unique, counts = np.unique(y, return_counts=True)

for label, count in zip(unique, counts):
    print(f"Label {label}: {count:,}")

print("\nVerification complete.")