FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

ARG LLVM_MAJOR=18
ARG RUST_TOOLCHAIN=1.88.0

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    binutils \
    ca-certificates \
    curl \
    g++ \
    gcc \
    gnupg \
    make \
    tar \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key -o /etc/apt/trusted.gpg.d/apt.llvm.org.asc; \
    echo "deb http://apt.llvm.org/noble/ llvm-toolchain-noble-${LLVM_MAJOR} main" > /etc/apt/sources.list.d/llvm.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      clang-${LLVM_MAJOR}; \
    rm -rf /var/lib/apt/lists/*

RUN ln -sf /usr/bin/clang-${LLVM_MAJOR} /usr/local/bin/clang && \
    ln -sf /usr/bin/clang++-${LLVM_MAJOR} /usr/local/bin/clang++

RUN set -eux; \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none; \
    export PATH="/root/.cargo/bin:$PATH"; \
    rustup set profile minimal; \
    rustup toolchain install "${RUST_TOOLCHAIN}"; \
    rustup default "${RUST_TOOLCHAIN}"; \
    cargo --version; \
    rustc --version

ENV PATH=/root/.cargo/bin:$PATH

WORKDIR /workspace

CMD ["/bin/bash"]
