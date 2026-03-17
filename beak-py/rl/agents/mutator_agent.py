"""PPO-based mutator selection agent."""

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.distributions import Categorical

from ..config import MutatorAgentConfig
from ..replay_buffer import RolloutBuffer


class ActorCritic(nn.Module):
    def __init__(self, state_dim: int, action_dim: int, hidden_dims: list[int]):
        super().__init__()
        layers = []
        prev_dim = state_dim
        for h in hidden_dims:
            layers.extend([nn.Linear(prev_dim, h), nn.ReLU()])
            prev_dim = h

        self.shared = nn.Sequential(*layers)
        self.actor = nn.Linear(prev_dim, action_dim)
        self.critic = nn.Linear(prev_dim, 1)

    def forward(self, x: torch.Tensor) -> tuple[Categorical, torch.Tensor]:
        features = self.shared(x)
        logits = self.actor(features)
        value = self.critic(features)
        dist = Categorical(logits=logits)
        return dist, value.squeeze(-1)


class MutatorAgent:
    """PPO agent for mutator arm selection."""

    def __init__(self, config: MutatorAgentConfig | None = None):
        self.config = config or MutatorAgentConfig()
        self.device = torch.device("cpu")

        self.model = ActorCritic(
            self.config.state_dim,
            self.config.num_arms,
            self.config.hidden_dims,
        ).to(self.device)

        self.optimizer = optim.Adam(
            self.model.parameters(), lr=self.config.learning_rate
        )
        self.buffer = RolloutBuffer()
        self.step_count = 0
        self.update_count = 0

        self._last_state: np.ndarray | None = None
        self._last_log_prob: float = 0.0
        self._last_value: float = 0.0

    def select_action(self, state_vec: list[float]) -> int:
        state = self._to_tensor(state_vec)

        if self.step_count < self.config.warmup_steps:
            action = np.random.randint(0, self.config.num_arms)
            with torch.no_grad():
                dist, value = self.model(state)
                self._last_log_prob = dist.log_prob(torch.tensor(action)).item()
                self._last_value = value.item()
        else:
            with torch.no_grad():
                dist, value = self.model(state)
                action = dist.sample().item()
                self._last_log_prob = dist.log_prob(torch.tensor(action)).item()
                self._last_value = value.item()

        self._last_state = np.array(state_vec, dtype=np.float32)
        self.step_count += 1
        return action

    def update(self, arm: int, reward: float, new_state_vec: list[float]):
        if self._last_state is None:
            return

        self.buffer.push(
            state=self._last_state,
            action=arm,
            reward=reward,
            log_prob=self._last_log_prob,
            value=self._last_value,
        )

        if len(self.buffer) >= self.config.update_every:
            self._train_ppo()
            self.buffer.clear()

    def _train_ppo(self):
        if len(self.buffer) == 0:
            return

        with torch.no_grad():
            last_state = self._to_tensor(self.buffer.states[-1].tolist())
            _, last_value = self.model(last_state)
            last_val = last_value.item()

        advantages, returns = self.buffer.compute_gae(
            self.config.gamma, self.config.gae_lambda, last_val
        )

        states = torch.tensor(
            np.array(self.buffer.states), dtype=torch.float32, device=self.device
        )
        actions = torch.tensor(self.buffer.actions, dtype=torch.long, device=self.device)
        old_log_probs = torch.tensor(
            self.buffer.log_probs, dtype=torch.float32, device=self.device
        )
        advantages_t = torch.tensor(advantages, dtype=torch.float32, device=self.device)
        returns_t = torch.tensor(returns, dtype=torch.float32, device=self.device)

        advantages_t = (advantages_t - advantages_t.mean()) / (
            advantages_t.std() + 1e-8
        )

        for _ in range(self.config.ppo_epochs):
            dist, values = self.model(states)
            new_log_probs = dist.log_prob(actions)
            entropy = dist.entropy().mean()

            ratio = torch.exp(new_log_probs - old_log_probs)
            surr1 = ratio * advantages_t
            surr2 = (
                torch.clamp(
                    ratio,
                    1.0 - self.config.clip_epsilon,
                    1.0 + self.config.clip_epsilon,
                )
                * advantages_t
            )

            actor_loss = -torch.min(surr1, surr2).mean()
            critic_loss = nn.functional.mse_loss(values, returns_t)
            loss = (
                actor_loss
                + self.config.value_coef * critic_loss
                - self.config.entropy_coef * entropy
            )

            self.optimizer.zero_grad()
            loss.backward()
            nn.utils.clip_grad_norm_(
                self.model.parameters(), self.config.max_grad_norm
            )
            self.optimizer.step()

        self.update_count += 1

    def _to_tensor(self, state_vec: list[float]) -> torch.Tensor:
        arr = np.array(state_vec, dtype=np.float32)
        if len(arr) < self.config.state_dim:
            arr = np.pad(arr, (0, self.config.state_dim - len(arr)))
        elif len(arr) > self.config.state_dim:
            arr = arr[: self.config.state_dim]
        return torch.tensor(arr, dtype=torch.float32, device=self.device).unsqueeze(0)

    def get_action_probs(self, state_vec: list[float]) -> list[float]:
        state = self._to_tensor(state_vec)
        with torch.no_grad():
            dist, _ = self.model(state)
            return dist.probs.squeeze(0).tolist()

    def get_entropy(self) -> float:
        if self._last_state is None:
            return float(np.log(self.config.num_arms))
        state = self._to_tensor(self._last_state.tolist())
        with torch.no_grad():
            dist, _ = self.model(state)
            return dist.entropy().item()

    def save(self, path: str):
        torch.save(
            {
                "model": self.model.state_dict(),
                "optimizer": self.optimizer.state_dict(),
                "step_count": self.step_count,
                "update_count": self.update_count,
            },
            path,
        )

    def load(self, path: str):
        ckpt = torch.load(path, map_location=self.device, weights_only=True)
        self.model.load_state_dict(ckpt["model"])
        self.optimizer.load_state_dict(ckpt["optimizer"])
        self.step_count = ckpt["step_count"]
        self.update_count = ckpt["update_count"]
