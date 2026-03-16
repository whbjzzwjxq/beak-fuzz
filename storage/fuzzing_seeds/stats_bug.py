import json
from pathlib import Path
import sys

def analyze_bug_file(path):
    bug_sigs = set()
    bucket_contexts = set()
    mismatch_patterns = set()
    instr_sigs = set()

    max_depth = 0
    total_bugs = 0

    with open(path) as f:
        for line in f:
            r = json.loads(line)
            total_bugs += 1

            bucket_sig = r["bucket_hits_sig"]
            mism = tuple(tuple(x) for x in r["mismatch_regs"])
            backend_err = r["backend_error"]
            oracle_err = r["oracle_error"]

            bug_sig = (bucket_sig, mism, backend_err, oracle_err)
            bug_sigs.add(bug_sig)

            bucket_contexts.add(bucket_sig)

            for m in mism:
                mismatch_patterns.add(tuple(m))

            instr_sigs.add(tuple(r["instructions"]))

            max_depth = max(max_depth, r.get("micro_op_count", 0))

    return {
        "total_bugs": total_bugs,
        "unique_bug_signatures": len(bug_sigs),
        "unique_bucket_contexts": len(bucket_contexts),
        "unique_mismatch_patterns": len(mismatch_patterns),
        "unique_instruction_sequences": len(instr_sigs),
        "max_bug_depth": max_depth,
    }


def print_bug_summary(stats):
    for k, v in stats.items():
        print(f"{k}: {v}")


if __name__ == "__main__":
    stats = analyze_bug_file(sys.argv[-1])
    print_bug_summary(stats)
