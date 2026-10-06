FROM ubuntu AS builder
WORKDIR /project

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc-multilib clang llvm libelf-dev linux-libc-dev \
    libbpf-dev bpftool pkgconf cmake \
    libzstd-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . .
RUN cmake -S . -B build
RUN cmake --build build

FROM scratch AS artifact
COPY --from=builder /project/build/minimal /minimal
