FROM ubuntu AS builder
WORKDIR /project

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc-multilib clang llvm libelf-dev linux-libc-dev \
    libbpf-dev bpftool pkgconf cmake \
    libzstd-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . .
RUN cmake -S . -B build -DCOMPILE_STATIC=ON -DGENERATE_VMLINUX=OFF
RUN cmake --build build

FROM ubuntu AS artifact
RUN apt-get update && apt-get install -y --no-install-recommends libbpf0 libelf1 zlib1g libzstd1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /project/build/auditor /usr/local/bin/auditor
ENTRYPOINT ["/usr/local/bin/auditor"]
