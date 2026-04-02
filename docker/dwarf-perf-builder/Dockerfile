FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
# Reproducible builds should override this explicitly when needed.
ENV SOURCE_DATE_EPOCH=1735689600
ENV DWARF_PERF_WORKDIR=/workspace
ENV DWARF_PERF_DEBUG_PREFIX_MAP=-fdebug-prefix-map=/workspace=/workspace

ARG LLVM_MAJOR=18
ARG RUST_TOOLCHAIN=1.88.0

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    binutils \
    build-essential \
    ca-certificates \
    cmake \
    curl \
    file \
    g++ \
    gcc \
    git \
    gnupg \
    jq \
    make \
    ninja-build \
    pkg-config \
    python3 \
    python3-venv \
    tar \
    time \
    unzip \
    wget \
    xz-utils \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key > /etc/apt/trusted.gpg.d/apt.llvm.org.asc; \
    echo "deb http://apt.llvm.org/noble/ llvm-toolchain-noble-${LLVM_MAJOR} main" > /etc/apt/sources.list.d/llvm.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      clang-${LLVM_MAJOR} \
      lld-${LLVM_MAJOR} \
      libclang-${LLVM_MAJOR}-dev \
      libpolly-${LLVM_MAJOR}-dev \
      llvm-${LLVM_MAJOR} \
      llvm-${LLVM_MAJOR}-dev \
      llvm-${LLVM_MAJOR}-tools; \
    rm -rf /var/lib/apt/lists/*

RUN ln -sf /usr/bin/clang-${LLVM_MAJOR} /usr/local/bin/clang && \
    ln -sf /usr/bin/clang++-${LLVM_MAJOR} /usr/local/bin/clang++ && \
    ln -sf /usr/bin/llvm-ar-${LLVM_MAJOR} /usr/local/bin/llvm-ar && \
    ln -sf /usr/bin/llvm-nm-${LLVM_MAJOR} /usr/local/bin/llvm-nm && \
    ln -sf /usr/bin/llvm-ranlib-${LLVM_MAJOR} /usr/local/bin/llvm-ranlib

RUN set -eux; \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none; \
    export PATH="/root/.cargo/bin:$PATH"; \
    rustup set profile minimal; \
    rustup toolchain install "${RUST_TOOLCHAIN}" --component rustfmt --component clippy; \
    rustup default "${RUST_TOOLCHAIN}"; \
    cargo --version; \
    rustc --version

ENV PATH=/root/.cargo/bin:/usr/lib/llvm-18/bin:$PATH
ENV LLVM_SYS_181_PREFIX=/usr/lib/llvm-18
ENV LLVM_CONFIG_PATH=/usr/lib/llvm-18/bin/llvm-config

WORKDIR /workspace

CMD ["/bin/bash"]
