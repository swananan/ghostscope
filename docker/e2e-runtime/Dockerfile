FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    curl \
    docker.io \
    gnupg \
    libffi8 \
    libstdc++6 \
    libtinfo6 \
    libxml2 \
    libzstd1 \
    procps \
    python3 \
    wget \
    zlib1g \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key > /etc/apt/trusted.gpg.d/apt.llvm.org.asc; \
    echo 'deb http://apt.llvm.org/noble/ llvm-toolchain-noble-18 main' > /etc/apt/sources.list.d/llvm.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      libffi-dev \
      libpolly-18-dev \
      libxml2-dev \
      llvm-18 \
      llvm-18-dev \
      libzstd-dev \
      zlib1g-dev; \
    rm -rf /var/lib/apt/lists/*

ENV LLVM_SYS_181_PREFIX=/usr/lib/llvm-18
ENV LLVM_CONFIG_PATH=/usr/lib/llvm-18/bin/llvm-config

WORKDIR /workspace

CMD ["/bin/bash"]
