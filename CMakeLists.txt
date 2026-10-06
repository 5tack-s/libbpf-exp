cmake_minimum_required(VERSION 3.18)
project(minimal C)

find_program(BPFTOOL bpftool REQUIRED)
find_program(CLANG clang REQUIRED)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(BPF_CFLAGS -g -O2 -target bpf -D__TARGET_ARCH_x86)


set(SRC
${CMAKE_SOURCE_DIR}/src/minimal.c
)

set(BPF
${CMAKE_SOURCE_DIR}/src/minimal.bpf.c
)

set(GEN ${CMAKE_SOURCE_DIR}/include/)
set(BPF_OBJECT ${GEN}/minimal.bpf.o)
set(BPF_SKEL ${CMAKE_SOURCE_DIR}/include/minimal.skel.h)


#$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

add_custom_command(
    OUTPUT ${GEN}/vmlinux.h
    COMMAND sh -c "${BPFTOOL} btf dump file /sys/kernel/btf/vmlinux format c > ${GEN}/vmlinux.h"
    VERBATIM
)

#   execsnoop.bpf.o: execsnoop.bpf.c vmlinux.h
#    $(CLANG) $(BPF_CFLAGS) -c $< -o $@

add_custom_command(
    OUTPUT ${BPF_OBJECT}
    DEPENDS ${GEN}/vmlinux.h ${BPF}
    COMMAND ${CLANG} ${BPF_CFLAGS} -I ${GEN} -c ${BPF} -o ${BPF_OBJECT}
    VERBATIM 
)

#  Step 3: Generate the skeleton header from the compiled BPF object
#    execsnoop.skel.h: execsnoop.bpf.o
#    $(BPFTOOL) gen skeleton $< > $@
add_custom_command(
    OUTPUT ${BPF_SKEL}
    DEPENDS ${BPF_OBJECT}
    COMMAND sh -c "${BPFTOOL} gen skeleton ${BPF_OBJECT} > ${BPF_SKEL}"
    VERBATIM
)

#   Step 4: Compile the userspace program with the embedded skeleton
#       execsnoop: execsnoop.c execsnoop.skel.h
#       $(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)


add_executable(${CMAKE_PROJECT_NAME} ${SRC} ${BPF_SKEL})
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE ${GEN})
target_link_options(${CMAKE_PROJECT_NAME} PRIVATE -static)
target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE -g -O2 -Wall)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE bpf elf z zstd)