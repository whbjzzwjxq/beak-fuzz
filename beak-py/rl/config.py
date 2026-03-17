"""Hyperparameter configuration for RL agents."""

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class MutatorAgentConfig:
    num_arms: int = 8
    state_dim: int = 23  # 9 base + 6 type_dist + 8 per-arm rewards
    hidden_dims: list[int] = field(default_factory=lambda: [64, 64])
    learning_rate: float = 3e-4
    gamma: float = 0.99
    gae_lambda: float = 0.95
    clip_epsilon: float = 0.2
    entropy_coef: float = 0.2
    value_coef: float = 0.5
    max_grad_norm: float = 0.5
    update_every: int = 32
    ppo_epochs: int = 4
    batch_size: int = 16
    warmup_steps: int = 200


@dataclass
class SchedulerAgentConfig:
    state_dim: int = 15
    hidden_dims: list[int] = field(default_factory=lambda: [64, 64])
    learning_rate: float = 3e-4
    gamma: float = 0.99
    update_every: int = 64
    warmup_steps: int = 500


@dataclass
class InjectionAgentConfig:
    state_dim: int = 10
    max_step: int = 1000
    num_step_bins: int = 50
    hidden_dims: list[int] = field(default_factory=lambda: [64, 64])
    learning_rate: float = 1e-3
    gamma: float = 0.99
    epsilon_start: float = 1.0
    epsilon_end: float = 0.05
    epsilon_decay: int = 5000
    buffer_size: int = 10000
    batch_size: int = 32
    target_update_every: int = 100
    warmup_steps: int = 200


@dataclass
class ServerConfig:
    socket_path: str = "/tmp/beak-rl.sock"
    log_dir: str = "output/rl_logs"
    checkpoint_dir: str = "output/rl_checkpoints"
    checkpoint_every: int = 1000
    tensorboard: bool = True
    mutator: MutatorAgentConfig = field(default_factory=MutatorAgentConfig)
    scheduler: SchedulerAgentConfig = field(default_factory=SchedulerAgentConfig)
    injection: InjectionAgentConfig = field(default_factory=InjectionAgentConfig)
