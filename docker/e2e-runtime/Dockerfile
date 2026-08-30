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
    echo 'deb http://apt.llvm.org/noble/ llvm-toolchain-noble-22 main' > /etc/apt/sources.list.d/llvm.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      libffi-dev \
      libpolly-22-dev \
      libxml2-dev \
      llvm-22 \
      llvm-22-dev \
      libzstd-dev \
      zlib1g-dev; \
    rm -rf /var/lib/apt/lists/*

ENV LLVM_SYS_221_PREFIX=/usr/lib/llvm-22
ENV LLVM_CONFIG_PATH=/usr/lib/llvm-22/bin/llvm-config

WORKDIR /workspace

CMD ["/bin/bash"]
