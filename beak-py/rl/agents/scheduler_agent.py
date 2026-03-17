"""PPO-based seed scheduler agent."""

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim

from ..config import SchedulerAgentConfig


class SeedScorer(nn.Module):
    """Outputs a priority score for seed selection given global state."""

    def __init__(self, state_dim: int, hidden_dims: list[int]):
        super().__init__()
        layers = []
        prev_dim = state_dim
        for h in hidden_dims:
            layers.extend([nn.Linear(prev_dim, h), nn.ReLU()])
            prev_dim = h
        layers.append(nn.Linear(prev_dim, 1))
        self.net = nn.Sequential(*layers)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x).squeeze(-1)


class SchedulerAgent:
    """Learns to prioritize corpus entries for mutation.

    Given a global fuzzer state vector, outputs an index into the corpus
    by scoring corpus_size candidates and sampling proportionally.
    For now uses a simplified approach: the global state maps to a
    distribution over position buckets.
    """

    def __init__(self, config: SchedulerAgentConfig | None = None):
        self.config = config or SchedulerAgentConfig()
        self.device = torch.device("cpu")
        self.scorer = SeedScorer(
            self.config.state_dim, self.config.hidden_dims
        ).to(self.device)
        self.optimizer = optim.Adam(
            self.scorer.parameters(), lr=self.config.learning_rate
        )
        self.step_count = 0
        self._history: list[tuple[np.ndarray, int, float]] = []

    def select_seed(self, state_vec: list[float], corpus_size: int) -> int:
        if corpus_size == 0:
            return 0

        if self.step_count < self.config.warmup_steps:
            self.step_count += 1
            return np.random.randint(0, corpus_size)

        self.step_count += 1
        # Use the scorer to produce a "temperature" that biases toward
        # recent vs old corpus entries.
        state = self._to_tensor(state_vec)
        with torch.no_grad():
            score = self.scorer(state).item()

        bias = torch.sigmoid(torch.tensor(score)).item()
        # bias ∈ (0,1): higher bias → prefer newer entries (higher index)
        indices = np.arange(corpus_size, dtype=np.float64)
        weights = np.exp(bias * indices / max(corpus_size - 1, 1))
        weights /= weights.sum()
        return int(np.random.choice(corpus_size, p=weights))

    def update(self, state_vec: list[float], chosen_idx: int, reward: float):
        arr = np.array(state_vec, dtype=np.float32)
        self._history.append((arr, chosen_idx, reward))

        if len(self._history) >= self.config.update_every:
            self._train()
            self._history.clear()

    def _train(self):
        if not self._history:
            return

        states = torch.tensor(
            np.array([h[0] for h in self._history]),
            dtype=torch.float32,
            device=self.device,
        )
        rewards = torch.tensor(
            [h[2] for h in self._history],
            dtype=torch.float32,
            device=self.device,
        )
        rewards = (rewards - rewards.mean()) / (rewards.std() + 1e-8)

        scores = self.scorer(states)
        loss = -(scores * rewards).mean()

        self.optimizer.zero_grad()
        loss.backward()
        self.optimizer.step()

    def _to_tensor(self, state_vec: list[float]) -> torch.Tensor:
        arr = np.array(state_vec, dtype=np.float32)
        if len(arr) < self.config.state_dim:
            arr = np.pad(arr, (0, self.config.state_dim - len(arr)))
        elif len(arr) > self.config.state_dim:
            arr = arr[: self.config.state_dim]
        return torch.tensor(arr, dtype=torch.float32, device=self.device).unsqueeze(0)

    def save(self, path: str):
        torch.save(
            {
                "scorer": self.scorer.state_dict(),
                "optimizer": self.optimizer.state_dict(),
                "step_count": self.step_count,
            },
            path,
        )

    def load(self, path: str):
        ckpt = torch.load(path, map_location=self.device, weights_only=True)
        self.scorer.load_state_dict(ckpt["scorer"])
        self.optimizer.load_state_dict(ckpt["optimizer"])
        self.step_count = ckpt["step_count"]
