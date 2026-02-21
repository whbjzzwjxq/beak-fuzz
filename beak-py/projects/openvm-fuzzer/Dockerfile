FROM debian:bookworm AS openvm

# Run docker image in non interactive mode
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential ca-certificates clang cmake curl dialog gcc git \
    jq libgmp-dev libgrpc++-dev libomp-dev libsecp256k1-dev \
    libssl-dev libsodium-dev libpqxx-dev nasm nlohmann-json3-dev  \
    pkg-config protobuf-compiler python3 python3-pip qemu-system \
    ssh uuid-dev vim xz-utils && \
    rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Install Rust
ARG RUST_VERSION="nightly-2026-01-01"
RUN curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs | \
    bash -s -- -y --profile minimal --default-toolchain=${RUST_VERSION}
ENV PATH="/root/.cargo/bin:${PATH}"

# Install RISC-V components needed for Oracle and Prover
RUN rustup target add riscv32im-unknown-none-elf && \
    rustup component add llvm-tools-preview rust-src --toolchain ${RUST_VERSION}

# Setup the app directory
WORKDIR /app

# Copy dependency files first to leverage Docker cache
COPY pyproject.toml .
COPY libs/zkvm-fuzzer-utils/pyproject.toml libs/zkvm-fuzzer-utils/
COPY projects/openvm-fuzzer/pyproject.toml projects/openvm-fuzzer/

# Copy the rest of the source code
COPY . .

# Synchronize dependencies
# We use --frozen to ensure consistency if uv.lock is present, or just sync.
RUN uv sync

# Standard Entrypoint
ENTRYPOINT ["uv", "run", "openvm-fuzzer"]
CMD ["install", "--zkvm-src", "./openvm-src", "--commit-or-branch", "bmk-f038", "--out-root", "./out"]
