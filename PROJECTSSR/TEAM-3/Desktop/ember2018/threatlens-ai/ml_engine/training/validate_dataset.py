import json
from collections import Counter

file_path = r"C:\Users\HP\Desktop\ember2018\merged_train.jsonl"

expected_keys = None
total_records = 0
invalid_json = 0
missing_key_records = 0
duplicate_sha = 0

label_counter = Counter()
sha256_seen = set()

print("Validating dataset...\n")

with open(file_path, "r", encoding="utf-8") as f:
    for line in f:
        total_records += 1

        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            invalid_json += 1
            continue

        # Check schema consistency
        keys = set(record.keys())

        if expected_keys is None:
            expected_keys = keys

        if keys != expected_keys:
            missing_key_records += 1

        # Label distribution
        label_counter[record["label"]] += 1

        # Duplicate SHA256
        sha = record["sha256"]

        if sha in sha256_seen:
            duplicate_sha += 1
        else:
            sha256_seen.add(sha)

        # Progress update every 100,000 records
        if total_records % 100000 == 0:
            print(f"{total_records:,} records checked...")

print("\n==============================")
print("VALIDATION REPORT")
print("==============================")

print(f"Total records           : {total_records:,}")
print(f"Invalid JSON records    : {invalid_json}")
print(f"Schema mismatches       : {missing_key_records}")
print(f"Duplicate SHA256 hashes : {duplicate_sha}")

print("\nLabel Distribution")

for label, count in sorted(label_counter.items()):
    print(f"Label {label}: {count:,}")

print("\nUnique SHA256 hashes:", len(sha256_seen))
