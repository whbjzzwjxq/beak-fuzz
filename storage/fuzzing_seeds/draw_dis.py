import re
import matplotlib.pyplot as plt

INPUT_FILE = "bandit_log.txt"

distributions = []

with open(INPUT_FILE) as f:
    for line in f:
        matches = re.findall(r"\[(.*?)\]", line)
        for m in matches:
            try:
                nums = list(map(int, m.split(",")))
                distributions.append(nums)
            except ValueError:
                pass  # ignore non-numeric brackets

if not distributions:
    raise RuntimeError("No valid distributions found")

# convert to weights
weights = []
for dist in distributions:
    total = sum(dist)
    weights.append([v / total for v in dist])

num_arms = len(weights[0])
steps = [i * 100 for i in range(len(weights))]

arm_series = list(zip(*weights))

plt.figure(figsize=(10,6))

for arm_id, series in enumerate(arm_series):
    plt.plot(steps, series, label=f"Arm {arm_id}")

plt.xlabel("Iteration")
plt.ylabel("Arm weight")
plt.title("Bandit Arm Weights Over Time")
plt.legend()
plt.grid(True)

plt.tight_layout()
plt.show()
