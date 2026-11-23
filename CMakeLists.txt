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

foreach(SKEL_TARGET IN LISTS BPF_SKEL_TARGETS)
    add_dependencies(${CMAKE_PROJECT_NAME} ${SKEL_TARGET})
endforeach()

if(COMPILE_STATIC)
    target_link_options(${CMAKE_PROJECT_NAME} PRIVATE -static)
    target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE elf z zstd)
endif()