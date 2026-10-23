# Index production is separate so the pinned corpus compiler stays unchanged.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV LC_ALL=C.UTF-8
RUN apt-get update && apt-get install -y --no-install-recommends \
    binutils \
    dwz \
    gdb \
    python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
