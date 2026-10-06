# Processo para compilação:
1.
    
    sudo apt-get install -y \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    linux-headers-$(uname -r) \
    libbpf-dev \
    bpftool \
    pkg-config

2. Gerar vmlinux.h:

      `$ bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h`
   
3. Rodar cmake
