FROM ubuntu:20.04

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    wget \
    curl \
    git \
    build-essential \
    software-properties-common \
    gnupg \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

# Install LLVM 18
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - \
    && add-apt-repository "deb http://apt.llvm.org/focal/ llvm-toolchain-focal-18 main" \
    && apt-get update \
    && apt-get install -y \
        llvm-18 llvm-18-dev llvm-18-runtime \
        clang-18 libclang-18-dev \
        libpolly-18-dev \
        libzstd-dev zlib1g-dev libtinfo-dev libxml2-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Rust (version specified in rust-toolchain.toml will be used)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none
ENV PATH="/root/.cargo/bin:$PATH"

# Set LLVM environment variable
ENV LLVM_SYS_181_PREFIX=/usr/lib/llvm-18
ENV PATH="/usr/lib/llvm-18/bin:$PATH"

# Set working directory
WORKDIR /workspace

# Default command
CMD ["/bin/bash"]
