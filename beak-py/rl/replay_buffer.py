"""Experience replay buffer for RL agents."""

import random
from collections import deque
from dataclasses import dataclass

import numpy as np


@dataclass
class Transition:
    state: np.ndarray
    action: int
    reward: float
    next_state: np.ndarray | None = None
    done: bool = False


class ReplayBuffer:
    """Fixed-size ring buffer for experience replay (DQN-style)."""

    def __init__(self, capacity: int):
        self.buffer: deque[Transition] = deque(maxlen=capacity)

    def push(self, transition: Transition):
        self.buffer.append(transition)

    def sample(self, batch_size: int) -> list[Transition]:
        return random.sample(self.buffer, min(batch_size, len(self.buffer)))

    def __len__(self) -> int:
        return len(self.buffer)


class RolloutBuffer:
    """On-policy rollout buffer for PPO."""

    def __init__(self):
        self.states: list[np.ndarray] = []
        self.actions: list[int] = []
        self.rewards: list[float] = []
        self.log_probs: list[float] = []
        self.values: list[float] = []
        self.dones: list[bool] = []

    def push(
        self,
        state: np.ndarray,
        action: int,
        reward: float,
        log_prob: float,
        value: float,
        done: bool = False,
    ):
        self.states.append(state)
        self.actions.append(action)
        self.rewards.append(reward)
        self.log_probs.append(log_prob)
        self.values.append(value)
        self.dones.append(done)

    def clear(self):
        self.states.clear()
        self.actions.clear()
        self.rewards.clear()
        self.log_probs.clear()
        self.values.clear()
        self.dones.clear()

    def __len__(self) -> int:
        return len(self.states)

    def compute_gae(
        self, gamma: float, gae_lambda: float, last_value: float = 0.0
    ) -> tuple[np.ndarray, np.ndarray]:
        """Compute Generalized Advantage Estimation."""
        n = len(self.rewards)
        advantages = np.zeros(n, dtype=np.float32)
        returns = np.zeros(n, dtype=np.float32)

        last_gae = 0.0
        for t in reversed(range(n)):
            next_value = last_value if t == n - 1 else self.values[t + 1]
            next_non_terminal = 0.0 if self.dones[t] else 1.0
            delta = (
                self.rewards[t]
                + gamma * next_value * next_non_terminal
                - self.values[t]
            )
            last_gae = delta + gamma * gae_lambda * next_non_terminal * last_gae
            advantages[t] = last_gae
            returns[t] = advantages[t] + self.values[t]

        return advantages, returns
