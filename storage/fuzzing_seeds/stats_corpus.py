import json
from collections import defaultdict
import sys

def parse_bucket_sig(sig):
    if not sig:
        return []
    return sig.split(";")


def analyze_corpus(path):
    bucket_seen = set()
    combo_seen = set()
    bucket_freq = defaultdict(int)

    total_records = 0
    total_new_bucket_reward = 0

    instr_sigs = set()

    coverage_curve = []

    with open(path) as f:
        for line in f:
            r = json.loads(line)
            total_records += 1

            bucket_sig = r["bucket_hits_sig"]
            buckets = parse_bucket_sig(bucket_sig)

            combo_seen.add(bucket_sig)

            for b in buckets:
                bucket_seen.add(b)
                bucket_freq[b] += 1

            # metadata reward
            meta = r.get("metadata", {})
            total_new_bucket_reward += meta.get("new_bucket_id_count", 0)

            instr_sigs.add(tuple(r["instructions"]))

            coverage_curve.append(
                (total_records, len(bucket_seen), len(combo_seen))
            )

    rarity_score = sum(1.0 / f for f in bucket_freq.values())

    return {
        "records": total_records,
        "unique_bucket_ids": len(bucket_seen),
        "unique_bucket_combos": len(combo_seen),
        "rarity_score": rarity_score,
        "unique_programs": len(instr_sigs),
        "reward_sum": total_new_bucket_reward,
        "coverage_curve": coverage_curve,
    }


def print_summary(stats):
    print("records:", stats["records"])
    print("unique_bucket_ids:", stats["unique_bucket_ids"])
    print("unique_bucket_combos:", stats["unique_bucket_combos"])
    print("rarity_score:", round(stats["rarity_score"], 3))
    print("unique_programs:", stats["unique_programs"])
    print("reward_sum:", stats["reward_sum"])


if __name__ == "__main__":
    stats = analyze_corpus(sys.argv[-1])
    print_summary(stats)