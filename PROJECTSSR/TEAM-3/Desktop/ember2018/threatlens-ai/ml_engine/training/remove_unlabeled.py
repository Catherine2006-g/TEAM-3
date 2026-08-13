import json
from collections import Counter

input_file = r"C:\Users\HP\Desktop\ember2018\merged_train.jsonl"
output_file = r"C:\Users\HP\Desktop\ember2018\labeled_train.jsonl"

label_counter = Counter()
kept_records = 0
removed_records = 0

print("Removing unlabeled samples...\n")

with open(input_file, "r", encoding="utf-8") as infile, \
     open(output_file, "w", encoding="utf-8") as outfile:

    for line_number, line in enumerate(infile, start=1):
        record = json.loads(line)

        label = record["label"]

        if label == -1:
            removed_records += 1
            continue

        outfile.write(json.dumps(record) + "\n")

        kept_records += 1
        label_counter[label] += 1

        if line_number % 100000 == 0:
            print(f"Processed {line_number:,} records...")

print("\n==============================")
print("FILTERING COMPLETE")
print("==============================")

print(f"Records kept      : {kept_records:,}")
print(f"Records removed   : {removed_records:,}")

print("\nRemaining Labels")

for label in sorted(label_counter):
    print(f"Label {label}: {label_counter[label]:,}")

print(f"\nOutput saved as:\n{output_file}")
