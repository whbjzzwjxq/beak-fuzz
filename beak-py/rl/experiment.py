"""A/B experiment runner for comparing policy strategies.

Automates running multiple fuzzing campaigns with different policies
and random seeds, then aggregates results for visualization.

Usage:
    python -m beak_py.rl.experiment --config experiment.json
    python -m beak_py.rl.experiment --quick  # Quick sanity run
"""

import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ExperimentRun:
    name: str
    policy: str
    rng_seed: int
    iters: int = 5000
    extra_args: list[str] = field(default_factory=list)


@dataclass
class ExperimentConfig:
    runs: list[ExperimentRun]
    output_base_dir: str = "output/experiments"
    binary_path: str = ""
    seeds_jsonl: str = "storage/fuzzing_seeds/initial.jsonl"
    timeout_ms: int = 500
    max_instructions: int = 256
    initial_limit: int = 500
    rl_socket_path: str = "/tmp/beak-rl.sock"
    rl_server_cmd: str = "python -m beak_py.rl.server"


def default_experiment_config() -> ExperimentConfig:
    """Standard A/B: bandit vs linucb vs rl, 3 seeds each."""
    runs = []
    for seed in [2026, 2027, 2028]:
        for policy in ["bandit", "linucb", "rl"]:
            runs.append(ExperimentRun(
                name=f"{policy}-seed{seed}",
                policy=policy,
                rng_seed=seed,
            ))
    return ExperimentConfig(runs=runs)


def quick_experiment_config() -> ExperimentConfig:
    """Quick sanity run: 1 seed, 500 iters."""
    runs = []
    for policy in ["bandit", "linucb"]:
        runs.append(ExperimentRun(
            name=f"quick-{policy}",
            policy=policy,
            rng_seed=2026,
            iters=500,
        ))
    return ExperimentConfig(runs=runs)


class ExperimentRunner:
    def __init__(self, config: ExperimentConfig):
        self.config = config
        self.results: list[dict] = []

    def run_all(self):
        base_dir = Path(self.config.output_base_dir)
        base_dir.mkdir(parents=True, exist_ok=True)

        total = len(self.config.runs)
        for i, run in enumerate(self.config.runs):
            print(f"\n{'='*60}", file=sys.stderr)
            print(f"[Experiment {i+1}/{total}] {run.name} (policy={run.policy}, seed={run.rng_seed})", file=sys.stderr)
            print(f"{'='*60}", file=sys.stderr)

            run_dir = base_dir / run.name
            run_dir.mkdir(parents=True, exist_ok=True)

            rl_process = None
            if run.policy in ("rl", "external"):
                rl_process = self._start_rl_server(run_dir)
                time.sleep(2)

            start = time.time()
            success = self._run_fuzzer(run, run_dir)
            elapsed = time.time() - start

            if rl_process:
                rl_process.terminate()
                rl_process.wait()

            self.results.append({
                "name": run.name,
                "policy": run.policy,
                "rng_seed": run.rng_seed,
                "iters": run.iters,
                "elapsed_sec": elapsed,
                "success": success,
                "output_dir": str(run_dir),
            })

        summary_path = base_dir / "experiment_summary.json"
        with open(summary_path, "w") as f:
            json.dump(self.results, f, indent=2)
        print(f"\nExperiment summary written to {summary_path}", file=sys.stderr)

    def _start_rl_server(self, run_dir: Path) -> subprocess.Popen:
        cmd = self.config.rl_server_cmd.split() + [
            "--socket", self.config.rl_socket_path,
            "--log-dir", str(run_dir / "rl_logs"),
            "--checkpoint-dir", str(run_dir / "rl_checkpoints"),
        ]
        return subprocess.Popen(cmd, stderr=subprocess.PIPE)

    def _run_fuzzer(self, run: ExperimentRun, run_dir: Path) -> bool:
        if not self.config.binary_path:
            print(f"  [SKIP] No binary_path configured, would run: policy={run.policy} seed={run.rng_seed} iters={run.iters}", file=sys.stderr)
            return True

        cmd = [
            self.config.binary_path,
            "--seeds-jsonl", self.config.seeds_jsonl,
            "--timeout-ms", str(self.config.timeout_ms),
            "--max-instructions", str(self.config.max_instructions),
            "--initial-limit", str(self.config.initial_limit),
            "--iters", str(run.iters),
            "--rng-seed", str(run.rng_seed),
            "--policy", run.policy,
            "--output-dir", str(run_dir),
        ]

        if run.policy in ("rl", "external"):
            cmd.extend(["--rl-socket-path", self.config.rl_socket_path])

        cmd.extend(run.extra_args)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            if result.returncode != 0:
                print(f"  [FAIL] {result.stderr[:500]}", file=sys.stderr)
                return False
            return True
        except subprocess.TimeoutExpired:
            print("  [TIMEOUT]", file=sys.stderr)
            return False
        except FileNotFoundError:
            print(f"  [ERROR] Binary not found: {self.config.binary_path}", file=sys.stderr)
            return False


def main():
    parser = argparse.ArgumentParser(description="Beak-Fuzz A/B Experiment Runner")
    parser.add_argument("--config", type=Path, help="JSON config file")
    parser.add_argument("--quick", action="store_true", help="Quick sanity run")
    parser.add_argument("--binary", type=str, default="", help="Path to fuzz binary")
    args = parser.parse_args()

    if args.config:
        with open(args.config) as f:
            data = json.load(f)
        runs = [ExperimentRun(**r) for r in data.get("runs", [])]
        config = ExperimentConfig(
            runs=runs,
            **{k: v for k, v in data.items() if k != "runs"},
        )
    elif args.quick:
        config = quick_experiment_config()
    else:
        config = default_experiment_config()

    if args.binary:
        config.binary_path = args.binary

    runner = ExperimentRunner(config)
    runner.run_all()


if __name__ == "__main__":
    main()
