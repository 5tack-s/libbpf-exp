cmake_minimum_required(VERSION 3.18)

find_program(BPFTOOL bpftool)
find_program(CLANG clang REQUIRED)

set(CMAKE_C_COMPILER ${CLANG})
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(auditor C)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    set(BPF_ARCH x86)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    set(BPF_ARCH arm64)
else()
    message(FATAL_ERROR "Unsupported arch ${CMAKE_SYSTEM_PROCESSOR}")
endif()

message(STATUS "Detected arch: ${BPF_ARCH}")

set(BPF_CFLAGS -g -O2 -target bpf -D__TARGET_ARCH_${BPF_ARCH})

# clang -target bpf does not search the arch-specific system include
# directory, but <linux/types.h> (included by vmlinux.h) needs <asm/types.h>
# which only lives there. Add it explicitly so the BPF objects compile.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    set(LIBBPF_ARCH_INCLUDE_DIR /usr/include/aarch64-linux-gnu)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    set(LIBBPF_ARCH_INCLUDE_DIR /usr/include/x86_64-linux-gnu)
endif()
if(LIBBPF_ARCH_INCLUDE_DIR AND EXISTS ${LIBBPF_ARCH_INCLUDE_DIR})
    list(APPEND BPF_CFLAGS -I ${LIBBPF_ARCH_INCLUDE_DIR})
endif()

option(COMPILE_STATIC "Compile bpf statically" OFF)
option(GENERATE_VMLINUX "Generate vmlinux.h via bpftool at build time" ON)

# Source tree layout:
set(SRC
    ${CMAKE_SOURCE_DIR}/src/userspace/auditor.c
    ${CMAKE_SOURCE_DIR}/src/userspace/police.c
    ${CMAKE_SOURCE_DIR}/src/userspace/main.c
    ${CMAKE_SOURCE_DIR}/src/userspace/socket.c
)

set(BPF_NAMES auditor police)

set(BPF_SKELS "")
set(BPF_SKEL_TARGETS "")

set(GEN ${CMAKE_SOURCE_DIR}/gen)
set(INCLUDE ${CMAKE_SOURCE_DIR}/include)
set(USERSPACE ${CMAKE_SOURCE_DIR}/src/userspace)
set(BPF_SRC ${CMAKE_SOURCE_DIR}/src/bpf)

file(MAKE_DIRECTORY ${GEN})

# Write a minimal vmlinux.h with the structs needed by BPF programs.
# We do NOT rely on bpftool because it requires root/BTF and often fails.
# If the user has bpftool+BTF, they can regenerate vmlinux.h manually:
#   bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h
file(WRITE ${INCLUDE}/vmlinux.h "/* Minimal vmlinux.h - libbpf-exp */\n")
file(APPEND ${INCLUDE}/vmlinux.h "#ifndef __VMLINUX_H__\n")
file(APPEND ${INCLUDE}/vmlinux.h "#define __VMLINUX_H__\n")
file(APPEND ${INCLUDE}/vmlinux.h "\n")
file(APPEND ${INCLUDE}/vmlinux.h "#include <linux/types.h>\n")
file(APPEND ${INCLUDE}/vmlinux.h "\n")
file(APPEND ${INCLUDE}/vmlinux.h "/* This minimal environment lacks <stdbool.h>, umode_t and the\n")
file(APPEND ${INCLUDE}/vmlinux.h " * current/task_struct declarations that the BPF programs rely on, so\n")
file(APPEND ${INCLUDE}/vmlinux.h " * provide them here. */\n")
file(APPEND ${INCLUDE}/vmlinux.h "typedef _Bool bool;\n")
file(APPEND ${INCLUDE}/vmlinux.h "typedef unsigned short umode_t;\n")
file(APPEND ${INCLUDE}/vmlinux.h "\n")
file(APPEND ${INCLUDE}/vmlinux.h "/* Shorthand types used by the BPF programs (kernel headers only\n")
file(APPEND ${INCLUDE}/vmlinux.h " * provide __u64/__u32/etc.). */\n")
file(APPEND ${INCLUDE}/vmlinux.h "typedef __u64 u64;\n")
file(APPEND ${INCLUDE}/vmlinux.h "typedef __u32 u32;\n")
file(APPEND ${INCLUDE}/vmlinux.h "typedef __u16 u16;\n")
file(APPEND ${INCLUDE}/vmlinux.h "typedef __u8 u8;\n")
file(APPEND ${INCLUDE}/vmlinux.h "\n")
file(APPEND ${INCLUDE}/vmlinux.h "#ifndef BPF_NO_PRESERVE_ACCESS_INDEX\n")
file(APPEND ${INCLUDE}/vmlinux.h "#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)\n")
file(APPEND ${INCLUDE}/vmlinux.h "#endif\n")
file(APPEND ${INCLUDE}/vmlinux.h "\n")
file(APPEND ${INCLUDE}/vmlinux.h "struct file {\n")
file(APPEND ${INCLUDE}/vmlinux.h "    struct inode *f_inode;\n")
file(APPEND ${INCLUDE}/vmlinux.h "};\n")
file(APPEND ${INCLUDE}/vmlinux.h "struct inode {\n")
file(APPEND ${INCLUDE}/vmlinux.h "    umode_t i_mode;\n")
file(APPEND ${INCLUDE}/vmlinux.h "    unsigned long i_ino;\n")
file(APPEND ${INCLUDE}/vmlinux.h "};\n")
file(APPEND ${INCLUDE}/vmlinux.h "struct mm_struct {\n")
file(APPEND ${INCLUDE}/vmlinux.h "    struct file *exe_file;\n")
file(APPEND ${INCLUDE}/vmlinux.h "};\n")
file(APPEND ${INCLUDE}/vmlinux.h "\n")
file(APPEND ${INCLUDE}/vmlinux.h "struct task_struct {\n")
file(APPEND ${INCLUDE}/vmlinux.h "    struct mm_struct *mm;\n")
file(APPEND ${INCLUDE}/vmlinux.h "};\n")
file(APPEND ${INCLUDE}/vmlinux.h "\n")
file(APPEND ${INCLUDE}/vmlinux.h "/* pt_regs / user_pt_regs used by kprobe/kretprobe helpers. The\n")
file(APPEND ${INCLUDE}/vmlinux.h " * tracing helpers dereference these via __PT_REGS_CAST, so they must\n")
file(APPEND ${INCLUDE}/vmlinux.h " * be complete types matching the register layout clang expects for\n")
file(APPEND ${INCLUDE}/vmlinux.h " * the target arch. On x86_64 __PT_REGS_CAST is a no-op (uses struct\n")
file(APPEND ${INCLUDE}/vmlinux.h " * pt_regs directly); on arm64 it casts to struct user_pt_regs. */\n")
if(BPF_ARCH MATCHES "x86")
    file(APPEND ${INCLUDE}/vmlinux.h "/* x86_64: with __VMLINUX_H__ defined, tracing.h uses\n")
    file(APPEND ${INCLUDE}/vmlinux.h " * short register names (di, si, ax, ...). __PT_REGS_CAST is a\n")
    file(APPEND ${INCLUDE}/vmlinux.h " * no-op, so struct pt_regs itself must be complete with these\n")
    file(APPEND ${INCLUDE}/vmlinux.h " * exact field names. */\n")
    file(APPEND ${INCLUDE}/vmlinux.h "struct pt_regs {\n")
    file(APPEND ${INCLUDE}/vmlinux.h "    unsigned long di, si, dx, cx, r8, r9, r10;\n")
    file(APPEND ${INCLUDE}/vmlinux.h "    unsigned long sp, bp, ax, ip;\n")
    file(APPEND ${INCLUDE}/vmlinux.h "};\n")
elseif(BPF_ARCH MATCHES "arm64")
    file(APPEND ${INCLUDE}/vmlinux.h "/* arm64: __PT_REGS_CAST casts to 'struct user_pt_regs' and the\n")
    file(APPEND ${INCLUDE}/vmlinux.h " * tracing macros access regs[0]..regs[N]. */\n")
    file(APPEND ${INCLUDE}/vmlinux.h "struct pt_regs {\n")
    file(APPEND ${INCLUDE}/vmlinux.h "    unsigned long __pad;\n")
    file(APPEND ${INCLUDE}/vmlinux.h "};\n")
    file(APPEND ${INCLUDE}/vmlinux.h "\n")
    file(APPEND ${INCLUDE}/vmlinux.h "struct user_pt_regs {\n")
    file(APPEND ${INCLUDE}/vmlinux.h "    unsigned long regs[32];\n")
    file(APPEND ${INCLUDE}/vmlinux.h "};\n")
endif()
file(APPEND ${INCLUDE}/vmlinux.h "\n")
file(APPEND ${INCLUDE}/vmlinux.h "#ifndef BPF_NO_PRESERVE_ACCESS_INDEX\n")
file(APPEND ${INCLUDE}/vmlinux.h "#pragma clang attribute pop\n")
file(APPEND ${INCLUDE}/vmlinux.h "#endif\n")
file(APPEND ${INCLUDE}/vmlinux.h "\n")
file(APPEND ${INCLUDE}/vmlinux.h "#endif /* __VMLINUX_H__ */\n")

add_custom_target(vmlinux DEPENDS ${INCLUDE}/vmlinux.h)

foreach(NAME IN LISTS BPF_NAMES)
    set(SRC_FILE ${BPF_SRC}/${NAME}.bpf.c)
    set(OBJ ${GEN}/${NAME}.bpf.o)
    SET(SKEL ${INCLUDE}/${NAME}.skel.h)

    add_custom_command(
        OUTPUT ${OBJ}
        DEPENDS vmlinux ${INCLUDE}/vmlinux.h ${SRC_FILE} ${BPF_SRC}/${NAME}.bpf.h
        COMMAND ${CLANG} ${BPF_CFLAGS} -I ${INCLUDE} -I ${BPF_SRC} -c ${SRC_FILE} -o ${OBJ}
        VERBATIM
    )

    add_custom_command(
        OUTPUT ${SKEL}
        DEPENDS ${OBJ}
        COMMAND ${CMAKE_COMMAND} -E rm -f ${SKEL}.tmp
        COMMAND /bin/sh -c "${BPFTOOL} gen skeleton ${OBJ} > ${SKEL}.tmp && ${CMAKE_COMMAND} -E copy_if_different ${SKEL}.tmp ${SKEL}"
        COMMAND ${CMAKE_COMMAND} -E rm -f ${SKEL}.tmp
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        VERBATIM
    )

    add_custom_target(${NAME}-skel DEPENDS ${SKEL})
    list(APPEND BPF_SKELS ${SKEL})
    list(APPEND BPF_SKEL_TARGETS ${NAME}-skel)
endforeach()

add_executable(${CMAKE_PROJECT_NAME} ${SRC})
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE ${INCLUDE} ${GEN} ${USERSPACE} ${BPF_SRC})
target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE -g -O2 -Wall)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE bpf)

foreach(SKEL_TARGET IN LISTS BPF_SKEL_TARGETS)
    add_dependencies(${CMAKE_PROJECT_NAME} ${SKEL_TARGET})
endforeach()

if(COMPILE_STATIC)
    target_link_options(${CMAKE_PROJECT_NAME} PRIVATE -static)
    target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE elf z zstd)
endif()