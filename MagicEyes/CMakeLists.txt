# \copyright
# Copyright (c) 2024 by the lmp/magic_eyes project authors. All Rights Reserved.
#
# This file is open source software, licensed to you under the terms
# of the Apache License, Version 2.0 (the "License").  See the NOTICE file
# distributed with this work for additional information regarding copyright
# ownership.  You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
# -----------------------------------------------------------------------------------------
# \brief
#      lmp/magic_eyes 顶层 CMakeLists 文件
# -----------------------------------------------------------------------------------------
cmake_minimum_required(VERSION 3.10)

set(CMAKE_C_COMPILER gcc)
set(CMAKE_CXX_COMPILER g++)

set(PROJECT_NAME MagicEyes)
project(${PROJECT_NAME})

# 查看目标系统，目前仅支持Linux
if (NOT DEFINED OS_PLATFORM)
    string(TOLOWER ${CMAKE_SYSTEM_NAME} OS_PLATFORM)
endif ()
if (OS_PLATFORM MATCHES "linux")
    include(GNUInstallDirs)  # for CMAKE_INSTALL_INCLUDEDIR ......
    INCLUDE(CheckFunctionExists) # for command check_function_exists ......
    message(STATUS "${PROJECT_NAME} running in OS platform: ${OS_PLATFORM}")
else ()
    message(SEND_ERROR "${PROJECT_NAME} only support Linux platform now")
endif ()
# 查看CPU架构
if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "x86_64")
    set(ARCH "x86")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "arm")
    set(ARCH "arm")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "aarch64")
    set(ARCH "arm64")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "ppc64le")
    set(ARCH "powerpc")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "mips")
    set(ARCH "mips")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "riscv64")
    set(ARCH "riscv")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "loongarch64")
    set(ARCH "loongarch")
endif()

#lht增加：不同编译环境下，构建libbpf和bpftool的编译选项
set(CROSS_COMPILE "")
set(CC ${CMAKE_C_COMPILER})

#lht增加：cmake -Dcross_compilation_arm64=ON .. 来配置交叉编译arm64的环境
if(DEFINED TARCH AND TARCH STREQUAL arm64 OR TARCH STREQUAL aarch64)
    message(STATUS "Cross-compilation for arm64 is enabled.")
    set(ARCH "arm64")
    include(${PROJECT_SOURCE_DIR}/platforms/aarch64/arm64_linux_setup.cmake)
else()
endif()


# 判断CPU架构
# if (NOT DEFINED OS_ARCH)
#    string(TOLOWER ${CMAKE_HOST_SYSTEM_PROCESSOR} OS_ARCH)
#    message(STATUS "${PROJECT_NAME} running in OS ARCH： ${OS_ARCH}")
#else ()
#    message(STATUS "${PROJECT_NAME} will running in OS ARCH： ${OS_ARCH}")
# endif ()

# 创建代码生成目录，后面生成的skel代码均放在这里
set(CONFIG_SRC_GEN_DIR ${CMAKE_SOURCE_DIR}/src-gen)
if (NOT EXISTS ${CONFIG_SRC_GEN_DIR})
    message(STATUS "src-gen文件夹不存在，准备创建")
    file(MAKE_DIRECTORY ${CONFIG_SRC_GEN_DIR})
endif ()
include_directories(${CONFIG_SRC_GEN_DIR})

# 修改默认安装路径为 <build_dir>/install而不是/usr/local
# 可通过 cmake -DCMAKE_INSTALL_PREFIX=<install_dir> 修改路径
if (${CMAKE_INSTALL_PREFIX} STREQUAL "/usr/local")
    set(CMAKE_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/install/)
endif ()
message(STATUS "install directory： ${CMAKE_INSTALL_PREFIX}")

# include backend common source file
set(BPF_COMMON_FILES_DIR ${CMAKE_SOURCE_DIR}/src/backend/bpf_common_helper)
file(GLOB BPF_COMMON_FILES ${BPF_COMMON_FILES_DIR})
include_directories(${BPF_COMMON_FILES_DIR})
# include component source file
set(PROJECT_COMPONENT_FILES_DIR ${CMAKE_SOURCE_DIR}/src/backend/component_helper)
file(GLOB PROJECT_COMPONENT_FILES ${PROJECT_COMPONENT_FILES_DIR})
include_directories(${PROJECT_COMPONENT_FILES_DIR})

# Tell cmake where to find BpfObject module
list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/tools/cmake)

# Build vendored libbpf
include(ExternalProject)
# ExternalProject_Add()函数创建一个外部工程可以驱动下载、更新/补丁、配置、构建、安装和测试流程的自定义目标
# 编译libbpf
ExternalProject_Add(libbpf
        PREFIX libbpf
        SOURCE_DIR ${CMAKE_SOURCE_DIR}/libbpf/src
        CONFIGURE_COMMAND ""
        BUILD_COMMAND make
            ARCH=${ARCH}
            CC=${CC}
            BUILD_STATIC_ONLY=1
            OBJDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf
            DESTDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf
            INCLUDEDIR=
            LIBDIR=
            UAPIDIR=
            install install_uapi_headers
        BUILD_IN_SOURCE TRUE
        INSTALL_COMMAND ""
        STEP_TARGETS build
)
# 编译bpftool
ExternalProject_Add(bpftool
        PREFIX bpftool
        SOURCE_DIR ${CMAKE_SOURCE_DIR}/bpftool/src
        CONFIGURE_COMMAND ""
        BUILD_COMMAND make 
            ARCH=${ARCH}
            CROSS_COMPILE=${CROSS_COMPILE}
            bootstrap
            OUTPUT=${CMAKE_CURRENT_BINARY_DIR}/bpftool/
        BUILD_IN_SOURCE TRUE
        INSTALL_COMMAND ""
        STEP_TARGETS build
)
# Rust语言用，Rust需要编译 blazesym
find_program(CARGO_EXISTS cargo)
if(CARGO_EXISTS)
    ExternalProject_Add(blazesym
            PREFIX blazesym
            SOURCE_DIR ${CMAKE_SOURCE_DIR}/blazesym
            CONFIGURE_COMMAND ""
            BUILD_COMMAND cargo build --release
            BUILD_IN_SOURCE TRUE
            INSTALL_COMMAND ""
            STEP_TARGETS build
    )
endif()

set(BPFOBJECT_BPFTOOL_EXE ${CMAKE_CURRENT_BINARY_DIR}/bpftool/bootstrap/bpftool)
set(BPFOBJECT_VMLINUX_H ${CMAKE_SOURCE_DIR}/vmlinux/${ARCH}/vmlinux.h)
set(LIBBPF_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/libbpf)
set(LIBBPF_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf.a)
set(BPFOBJECT_CLANG_EXE clang)

find_package(BpfObject REQUIRED)
if (NOT BpfObject_FOUND)
    message(STATUS "BpfObject not found, please check")
endif ()

add_subdirectory(src/backend)
add_subdirectory(src/bridge)
add_subdirectory(src/magic_eyes_cli)
add_subdirectory(src/visualization)
