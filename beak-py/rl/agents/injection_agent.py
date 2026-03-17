"""DQN-based semantic injection step selection agent."""

import math
import random

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim

from ..config import InjectionAgentConfig
from ..replay_buffer import ReplayBuffer, Transition


class DQN(nn.Module):
    def __init__(self, state_dim: int, action_dim: int, hidden_dims: list[int]):
        super().__init__()
        layers = []
        prev_dim = state_dim
        for h in hidden_dims:
            layers.extend([nn.Linear(prev_dim, h), nn.ReLU()])
            prev_dim = h
        layers.append(nn.Linear(prev_dim, action_dim))
        self.net = nn.Sequential(*layers)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class InjectionAgent:
    """DQN agent for selecting semantic injection steps.

    Discretizes the step space into bins and learns Q-values for each bin.
    """

    def __init__(self, config: InjectionAgentConfig | None = None):
        self.config = config or InjectionAgentConfig()
        self.device = torch.device("cpu")

        self.policy_net = DQN(
            self.config.state_dim,
            self.config.num_step_bins,
            self.config.hidden_dims,
        ).to(self.device)
        self.target_net = DQN(
            self.config.state_dim,
            self.config.num_step_bins,
            self.config.hidden_dims,
        ).to(self.device)
        self.target_net.load_state_dict(self.policy_net.state_dict())
        self.target_net.eval()

        self.optimizer = optim.Adam(
            self.policy_net.parameters(), lr=self.config.learning_rate
        )
        self.buffer = ReplayBuffer(self.config.buffer_size)
        self.step_count = 0
        self.update_count = 0

    def _epsilon(self) -> float:
        return self.config.epsilon_end + (
            self.config.epsilon_start - self.config.epsilon_end
        ) * math.exp(-self.step_count / self.config.epsilon_decay)

    def _bin_to_step(self, bin_idx: int) -> int:
        bin_size = max(self.config.max_step // self.config.num_step_bins, 1)
        return bin_idx * bin_size + bin_size // 2

    def _step_to_bin(self, step: int) -> int:
        bin_size = max(self.config.max_step // self.config.num_step_bins, 1)
        return min(step // bin_size, self.config.num_step_bins - 1)

    def select_step(self, state_vec: list[float]) -> tuple[int, int]:
        """Returns (candidate_index=0, step). Candidate selection is done by caller."""
        state = self._to_tensor(state_vec)
        self.step_count += 1

        if random.random() < self._epsilon():
            bin_idx = random.randint(0, self.config.num_step_bins - 1)
        else:
            with torch.no_grad():
                q_values = self.policy_net(state)
                bin_idx = q_values.argmax(dim=1).item()

        return 0, self._bin_to_step(bin_idx)

    def update(self, state_vec: list[float], step: int, reward: float,
               next_state_vec: list[float] | None = None, done: bool = False):
        state = np.array(state_vec, dtype=np.float32)
        next_state = (
            np.array(next_state_vec, dtype=np.float32)
            if next_state_vec is not None
            else None
        )
        action = self._step_to_bin(step)

        self.buffer.push(
            Transition(
                state=state, action=action, reward=reward,
                next_state=next_state, done=done,
            )
        )

        if len(self.buffer) >= self.config.batch_size:
            self._train()

        self.update_count += 1
        if self.update_count % self.config.target_update_every == 0:
            self.target_net.load_state_dict(self.policy_net.state_dict())

    def _train(self):
        batch = self.buffer.sample(self.config.batch_size)

        states = torch.tensor(
            np.array([t.state for t in batch]),
            dtype=torch.float32, device=self.device,
        )
        actions = torch.tensor(
            [t.action for t in batch], dtype=torch.long, device=self.device
        )
        rewards = torch.tensor(
            [t.reward for t in batch], dtype=torch.float32, device=self.device
        )
        dones = torch.tensor(
            [t.done for t in batch], dtype=torch.float32, device=self.device
        )

        non_final_mask = ~dones.bool()
        non_final_next = torch.tensor(
            np.array([t.next_state for t in batch if t.next_state is not None]),
            dtype=torch.float32, device=self.device,
        ) if any(t.next_state is not None for t in batch) else None

        current_q = self.policy_net(states).gather(1, actions.unsqueeze(1)).squeeze(1)

        next_q = torch.zeros(len(batch), device=self.device)
        if non_final_next is not None and non_final_next.numel() > 0:
            with torch.no_grad():
                next_q[non_final_mask] = self.target_net(non_final_next).max(dim=1).values

        target_q = rewards + self.config.gamma * next_q * (1 - dones)
        loss = nn.functional.smooth_l1_loss(current_q, target_q)

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
                "policy_net": self.policy_net.state_dict(),
                "target_net": self.target_net.state_dict(),
                "optimizer": self.optimizer.state_dict(),
                "step_count": self.step_count,
                "update_count": self.update_count,
            },
            path,
        )

    def load(self, path: str):
        ckpt = torch.load(path, map_location=self.device, weights_only=True)
        self.policy_net.load_state_dict(ckpt["policy_net"])
        self.target_net.load_state_dict(ckpt["target_net"])
        self.optimizer.load_state_dict(ckpt["optimizer"])
        self.step_count = ckpt["step_count"]
        self.update_count = ckpt["update_count"]
