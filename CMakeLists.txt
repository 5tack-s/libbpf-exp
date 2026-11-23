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

option(COMPILE_STATIC "Compile bpf statically" OFF)
option(GENERATE_VMLINUX "Generate vmlinux.h via bpftool at build time" ON)

# Source tree layout:
#   src/userspace/  - userspace C libraries + main entry (police, auditor, socket, main)
#   src/bpf/        - BPF programs (police.bpf.c, auditor.bpf.c) and their headers
#   include/        - public headers + generated vmlinux.h + skeletons
#   gen/            - build output (BPF objects)
#   build/          - CMake build output
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

# Generate vmlinux.h from BTF if bpftool is available and generation is enabled.
# This requires root and a BTF-enabled kernel. If unavailable, falls back to
# a minimal vmlinux.h with the structs needed by the BPF programs.
if(GENERATE_VMLINUX AND BPFTOOL)
    execute_process(
        COMMAND ${BPFTOOL} btf dump file /sys/kernel/btf/vmlinux format c
        OUTPUT_FILE ${INCLUDE}/vmlinux.h
        ERROR_QUIET
        RESULT_VARIABLE vmlinux_gen_result
    )
    if(NOT vmlinux_gen_result EQUAL 0 OR NOT EXISTS ${INCLUDE}/vmlinux.h)
        message(STATUS "bpftool vmlinux dump failed, generating fallback vmlinux.h")
        file(WRITE ${INCLUDE}/vmlinux.h "/* Minimal vmlinux.h fallback */\n")
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
    endif()
else()
    message(STATUS "Skipping vmlinux.h generation (bpftool not found or GENERATE_VMLINUX=OFF)")
    file(WRITE ${INCLUDE}/vmlinux.h "/* Minimal vmlinux.h fallback */\n")
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
endif()

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
        COMMAND ${BPFTOOL} gen skeleton ${OBJ} > ${SKEL} 2>/dev/null || true
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

# Make sure the executable is rebuilt when any skel header changes.
foreach(SKEL_TARGET IN LISTS BPF_SKEL_TARGETS)
    add_dependencies(${CMAKE_PROJECT_NAME} ${SKEL_TARGET})
endforeach()

if(COMPILE_STATIC)
    target_link_options(${CMAKE_PROJECT_NAME} PRIVATE -static)
    target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE elf z zstd)
endif()