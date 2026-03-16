import json
from collections import Counter
import matplotlib.pyplot as plt
import sys
INPUT_FILE = sys.argv[-1]

bucket_counter = Counter()

with open(INPUT_FILE) as f:
    for line in f:
        rec = json.loads(line)

        for hit in rec.get("bucket_hits", []):
            bucket_id = hit.get("bucket_id")
            if bucket_id:
                bucket_counter[bucket_id] += 1

if not bucket_counter:
    raise RuntimeError("No bucket_id entries found")

labels = list(bucket_counter.keys())
counts = list(bucket_counter.values())

# -------- Bar Graph --------
plt.figure(figsize=(10,6))
plt.bar(labels, counts)
plt.xticks(rotation=45, ha="right")
plt.ylabel("Number of bugs")
plt.title("Bug Distribution by bucket_id")
plt.tight_layout()
plt.show()

# -------- Pie Chart --------
plt.figure(figsize=(8,8))
plt.pie(counts, labels=labels, autopct='%1.1f%%')
plt.title("Bug Variety by bucket_id")
plt.tight_layout()
plt.show()
