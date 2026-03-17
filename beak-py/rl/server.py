"""Unix domain socket server for RL agents.

Receives JSON requests from the Rust fuzzer, routes to appropriate agent,
and returns JSON responses. Supports concurrent connections.
"""

import json
import os
import signal
import socket
import sys
import threading
import time
from pathlib import Path

from .agents import InjectionAgent, MutatorAgent, SchedulerAgent
from .config import ServerConfig


class RLServer:
    def __init__(self, config: ServerConfig | None = None):
        self.config = config or ServerConfig()
        self.mutator_agent = MutatorAgent(self.config.mutator)
        self.scheduler_agent = SchedulerAgent(self.config.scheduler)
        self.injection_agent = InjectionAgent(self.config.injection)

        self.request_count = 0
        self.start_time = time.time()
        self._lock = threading.Lock()
        self._running = False
        self._server_socket: socket.socket | None = None

        os.makedirs(self.config.log_dir, exist_ok=True)
        os.makedirs(self.config.checkpoint_dir, exist_ok=True)

        self._metrics_log = open(
            Path(self.config.log_dir) / "rl_server_metrics.jsonl", "a"
        )

    def handle_request(self, data: dict) -> dict:
        req_type = data.get("type", "")
        req_id = data.get("request_id", 0)

        with self._lock:
            self.request_count += 1

            if req_type == "select_mutator":
                state_vec = self._extract_state_vec(data.get("state", {}))
                action = self.mutator_agent.select_action(state_vec)
                return {"action": action, "request_id": req_id}

            elif req_type == "update_mutator":
                arm = data.get("arm", 0)
                reward = data.get("reward", 0.0)
                state_vec = self._extract_state_vec(data.get("state", {}))
                self.mutator_agent.update(arm, reward, state_vec)
                self._maybe_log_metrics(state_vec, reward)
                self._maybe_checkpoint()
                return {"ok": True, "request_id": req_id}

            elif req_type == "select_seed":
                state_vec = self._extract_state_vec(data.get("state", {}))
                corpus_size = data.get("corpus_size", 1)
                idx = self.scheduler_agent.select_seed(state_vec, corpus_size)
                return {"action": idx, "request_id": req_id}

            elif req_type == "select_injection":
                state_vec = self._extract_state_vec(data.get("state", {}))
                candidates = data.get("candidates", [])
                if not candidates:
                    return {"candidate_idx": None, "step": None, "request_id": req_id}
                _, step = self.injection_agent.select_step(state_vec)
                return {"candidate_idx": 0, "step": step, "request_id": req_id}

            elif req_type == "update_injection":
                reward = data.get("reward", 0.0)
                step = data.get("step", 0)
                self.injection_agent.update([], step, reward)
                return {"ok": True, "request_id": req_id}

            else:
                return {"error": f"unknown request type: {req_type}", "request_id": req_id}

    def _extract_state_vec(self, state: dict) -> list[float]:
        """Convert FuzzerState JSON dict to flat feature vector."""
        vec = []
        vec.append(float(state.get("corpus_size", 0)))
        vec.append(float(state.get("unique_bucket_ids", 0)))
        vec.append(float(state.get("unique_signatures", 0)))
        vec.append(float(state.get("iteration", 0)))
        vec.append(float(state.get("time_since_last_novel", 0)))
        vec.append(float(state.get("cumulative_reward", 0)))
        vec.append(float(state.get("bug_count", 0)))

        seed_feat = state.get("seed_features", {})
        vec.append(float(seed_feat.get("instruction_count", 0)))
        vec.append(float(seed_feat.get("bucket_hit_count", 0)))

        type_dist = seed_feat.get("type_distribution", [0] * 6)
        for v in type_dist[:6]:
            vec.append(float(v))

        for r in state.get("recent_arm_rewards", []):
            vec.append(float(r))

        return vec

    def _maybe_log_metrics(self, state_vec: list[float], reward: float):
        if self.request_count % 100 != 0:
            return
        record = {
            "request_count": self.request_count,
            "elapsed_sec": time.time() - self.start_time,
            "mutator_step": self.mutator_agent.step_count,
            "mutator_updates": self.mutator_agent.update_count,
            "entropy": self.mutator_agent.get_entropy(),
            "last_reward": reward,
        }
        self._metrics_log.write(json.dumps(record) + "\n")
        self._metrics_log.flush()

    def _maybe_checkpoint(self):
        if self.request_count % self.config.checkpoint_every != 0:
            return
        ckpt_dir = Path(self.config.checkpoint_dir)
        self.mutator_agent.save(str(ckpt_dir / f"mutator_{self.request_count}.pt"))
        self.scheduler_agent.save(str(ckpt_dir / f"scheduler_{self.request_count}.pt"))
        self.injection_agent.save(str(ckpt_dir / f"injection_{self.request_count}.pt"))

    def _handle_connection(self, conn: socket.socket, addr):
        with conn:
            buf = conn.makefile("r")
            out = conn.makefile("w")
            for line in buf:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    resp = self.handle_request(data)
                    out.write(json.dumps(resp) + "\n")
                    out.flush()
                except json.JSONDecodeError:
                    out.write(json.dumps({"error": "invalid json"}) + "\n")
                    out.flush()
                except Exception as e:
                    out.write(json.dumps({"error": str(e)}) + "\n")
                    out.flush()

    def serve(self):
        sock_path = self.config.socket_path
        if os.path.exists(sock_path):
            os.unlink(sock_path)

        self._server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server_socket.bind(sock_path)
        self._server_socket.listen(5)
        self._running = True

        print(f"[RL Server] listening on {sock_path}", file=sys.stderr)

        def _shutdown(signum, frame):
            self._running = False
            if self._server_socket:
                self._server_socket.close()

        signal.signal(signal.SIGINT, _shutdown)
        signal.signal(signal.SIGTERM, _shutdown)

        try:
            while self._running:
                try:
                    conn, addr = self._server_socket.accept()
                    t = threading.Thread(
                        target=self._handle_connection, args=(conn, addr), daemon=True
                    )
                    t.start()
                except OSError:
                    break
        finally:
            if os.path.exists(sock_path):
                os.unlink(sock_path)
            self._metrics_log.close()
            print(
                f"[RL Server] shutdown after {self.request_count} requests",
                file=sys.stderr,
            )


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Beak-Fuzz RL Agent Server")
    parser.add_argument("--socket", default="/tmp/beak-rl.sock")
    parser.add_argument("--log-dir", default="output/rl_logs")
    parser.add_argument("--checkpoint-dir", default="output/rl_checkpoints")
    parser.add_argument("--checkpoint-every", type=int, default=1000)
    args = parser.parse_args()

    config = ServerConfig(
        socket_path=args.socket,
        log_dir=args.log_dir,
        checkpoint_dir=args.checkpoint_dir,
        checkpoint_every=args.checkpoint_every,
    )
    server = RLServer(config)
    server.serve()


if __name__ == "__main__":
    main()
