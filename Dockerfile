FROM ubuntu:20.04

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Base build/runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    wget \
    git \
    xz-utils \
    tar \
    pkg-config \
    build-essential \
    ninja-build \
    python3 \
    libzstd-dev zlib1g-dev libxml2-dev \
    && rm -rf /var/lib/apt/lists/*

# Install a modern CMake (>=3.20) from official binary tarball to avoid slow APT mirrors
ARG CMAKE_VER=3.29.6
RUN set -eux; \
    url1="https://cmake.org/files/v${CMAKE_VER%.*}/cmake-${CMAKE_VER}-linux-x86_64.tar.gz"; \
    url2="https://github.com/Kitware/CMake/releases/download/v${CMAKE_VER}/cmake-${CMAKE_VER}-linux-x86_64.tar.gz"; \
    echo "Downloading CMake ${CMAKE_VER}..."; \
    ( \
      curl -fL --retry 5 --retry-delay 3 --retry-all-errors -o /tmp/cmake.tar.gz "$url1" \
      || wget -O /tmp/cmake.tar.gz --tries=5 --waitretry=3 --retry-connrefused "$url1" \
      || curl -fL --retry 5 --retry-delay 3 --retry-all-errors -o /tmp/cmake.tar.gz "$url2" \
      || wget -O /tmp/cmake.tar.gz --tries=5 --waitretry=3 --retry-connrefused "$url2" \
    ); \
    tar -C /opt -xzf /tmp/cmake.tar.gz; \
    cmake_dir=$(tar -tzf /tmp/cmake.tar.gz | head -1 | cut -f1 -d'/'); \
    mv "/opt/${cmake_dir}" /opt/cmake; \
    ln -s /opt/cmake/bin/* /usr/local/bin/; \
    cmake --version; \
    rm -f /tmp/cmake.tar.gz

# Build and install LLVM 18.1.x from source with FFI disabled
# This removes the runtime dependency on libffi while keeping needed targets.
ARG LLVM_VER=18.1.8
RUN <<'SHELL'
set -eux
base_url="https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VER}"
tar_xz="llvm-project-${LLVM_VER}.src.tar.xz"
alt_url="https://codeload.github.com/llvm/llvm-project/tar.xz/refs/tags/llvmorg-${LLVM_VER}"
echo "Downloading LLVM ${LLVM_VER} source tarball..."
( \
  curl -fL --retry 5 --retry-delay 3 --retry-all-errors -o /tmp/llvm.tar.xz "$base_url/$tar_xz" \
  || wget -O /tmp/llvm.tar.xz --tries=5 --waitretry=3 --retry-connrefused "$base_url/$tar_xz" \
  || curl -fL --retry 5 --retry-delay 3 --retry-all-errors -o /tmp/llvm.tar.xz "$alt_url" \
  || wget -O /tmp/llvm.tar.xz --tries=5 --waitretry=3 --retry-connrefused "$alt_url" \
)
test -s /tmp/llvm.tar.xz
mkdir -p /tmp/llvm && tar -C /tmp/llvm --strip-components=1 -xf /tmp/llvm.tar.xz
cmake -G Ninja -S /tmp/llvm/llvm -B /tmp/llvm-build \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_ENABLE_PROJECTS=clang \
  -DLLVM_TARGETS_TO_BUILD="BPF;X86" \
  -DLLVM_BUILD_LLVM_DYLIB=ON \
  -DLLVM_LINK_LLVM_DYLIB=ON \
  -DLLVM_ENABLE_FFI=OFF \
  -DLLVM_ENABLE_TERMINFO=OFF \
  -DLLVM_ENABLE_ZLIB=ON \
  -DLLVM_ENABLE_ZSTD=ON \
  -DCMAKE_INSTALL_PREFIX=/opt/llvm-18
ninja -C /tmp/llvm-build install
# Wrap llvm-config to filter out any stray -lffi from system-libs output
if [ -x /opt/llvm-18/bin/llvm-config ]; then
  mv /opt/llvm-18/bin/llvm-config /opt/llvm-18/bin/llvm-config.real
  cat > /opt/llvm-18/bin/llvm-config <<'WRAP'
#!/bin/sh
REAL="/opt/llvm-18/bin/llvm-config.real"
# Capture stdout+stderr and original exit status
OUT="$($REAL "$@" 2>&1)"; RC=$?
if [ $RC -ne 0 ]; then
  printf '%s\n' "$OUT" >&2
  exit $RC
fi
# Filter only library flag queries; pass-through otherwise
case " $* " in
  *" --system-libs "*|*" --libs "*|*" --ldflags "*)
    printf '%s\n' "$OUT" | sed -E 's/(^|[[:space:]])-lffi([[:space:]]|$)/\1\2/g'
    ;;
  *)
    printf '%s\n' "$OUT"
    ;;
esac
exit 0
WRAP
  chmod +x /opt/llvm-18/bin/llvm-config
fi
rm -rf /tmp/llvm /tmp/llvm-build /tmp/llvm.tar.xz
SHELL

# Install Rust (version specified in rust-toolchain.toml will be used)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none
ENV PATH="/root/.cargo/bin:$PATH"

# Expose LLVM to llvm-sys/inkwell
ENV LLVM_SYS_181_PREFIX=/opt/llvm-18
ENV PATH="/opt/llvm-18/bin:$PATH"

# Set working directory
WORKDIR /workspace

# Default command
CMD ["/bin/bash"]
