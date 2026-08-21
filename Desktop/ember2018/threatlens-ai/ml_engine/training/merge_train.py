from pathlib import Path

# Folder containing the dataset
dataset_folder = Path(r"C:\Users\HP\Desktop\ember2018")

# Output file
output_file = dataset_folder / "merged_train.jsonl"

# List of training files
train_files = [
    "train_features_0.jsonl",
    "train_features_1.jsonl",
    "train_features_2.jsonl",
    "train_features_3.jsonl",
    "train_features_4.jsonl",
    "train_features_5.jsonl",
]

# Merge all training files
with open(output_file, "w", encoding="utf-8") as outfile:
    for filename in train_files:
        print(f"Merging {filename}...")
        with open(dataset_folder / filename, "r", encoding="utf-8") as infile:
            for line in infile:
                outfile.write(line)

print("\nMerge completed successfully!")
print(f"Merged file created at:\n{output_file}")
