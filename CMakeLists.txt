cmake_minimum_required(VERSION 3.18)

find_program(BPFTOOL bpftool REQUIRED)
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

message(STATUS "Detected arch: ${CMAKE_SYSTEM_PROCESSOR}")

set(BPF_CFLAGS -g -O2 -target bpf -D__TARGET_ARCH_${BPF_ARCH})


option(COMPILE_STATIC "Compile bpf statically" OFF) # This really is only going to be used when using docker.

set(SRC
${CMAKE_SOURCE_DIR}/src/auditor.c
${CMAKE_SOURCE_DIR}/src/police.c
${CMAKE_SOURCE_DIR}/src/main.c
)

set(BPF_NAMES
auditor
police
)

set(BPF_SKELS "")

set(GEN ${CMAKE_SOURCE_DIR}/gen)
set(INCLUDE ${CMAKE_SOURCE_DIR}/include)

file(MAKE_DIRECTORY ${GEN})

#$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

add_custom_command(
    OUTPUT ${INCLUDE}/vmlinux.h
    COMMAND sh -c "${BPFTOOL} btf dump file /sys/kernel/btf/vmlinux format c > ${INCLUDE}/vmlinux.h"
    VERBATIM
)

#   execsnoop.bpf.o: execsnoop.bpf.c vmlinux.h
#    $(CLANG) $(BPF_CFLAGS) -c $< -o $@


foreach(NAME IN LISTS BPF_NAMES)
    set(SRC_FILE ${CMAKE_SOURCE_DIR}/src/${NAME}.bpf.c)
    set(OBJ ${GEN}/${NAME}.bpf.o)
    SET(SKEL ${INCLUDE}/${NAME}.skel.h)

    add_custom_command(
        OUTPUT ${OBJ}
        DEPENDS ${INCLUDE}/vmlinux.h ${SRC_FILE} ${CMAKE_SOURCE_DIR}/src/${NAME}.bpf.h
        COMMAND ${CLANG} ${BPF_CFLAGS} -I ${INCLUDE} -c ${SRC_FILE} -o ${OBJ}
        VERBATIM 
    )

#  Step 3: Generate the skeleton header from the compiled BPF object
#    execsnoop.skel.h: execsnoop.bpf.o
#    $(BPFTOOL) gen skeleton $< > $@
add_custom_command(
    OUTPUT ${SKEL}
    DEPENDS ${OBJ}
    COMMAND sh -c "${BPFTOOL} gen skeleton ${OBJ} > ${SKEL}"
    VERBATIM
)

list(APPEND BPF_SKELS ${SKEL})
endforeach()

#   Step 4: Compile the userspace program with the embedded skeleton
#       execsnoop: execsnoop.c execsnoop.skel.h
#       $(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)


add_executable(${CMAKE_PROJECT_NAME} ${SRC} ${BPF_SKELS})
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE ${INCLUDE})
target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE -g -O2 -Wall)

target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE bpf)

if(COMPILE_STATIC)
target_link_options(${CMAKE_PROJECT_NAME} PRIVATE -static)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE elf z zstd)
endif()