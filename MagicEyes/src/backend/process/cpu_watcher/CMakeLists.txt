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
#      cpu_watcher 工具 CMakeLists 文件
# -----------------------------------------------------------------------------------------

# 1. 工具名为 cpuwatcher 在process目录下
set(TOOL_NAME cpu_watcher)
set(CONTROLLER_NAME controller)
set(TOOL_BELONG_TO_MODULE process)
include_directories(${LIBBPF_INCLUDE_DIRS})
# 2. 查找bpf.c文件并保存在apps列表中
file(GLOB apps ${CMAKE_CURRENT_SOURCE_DIR}/bpf/*.bpf.c)

# 3.若不用Rust，则排除 profile.bpf.c
if(NOT CARGO_EXISTS)
    list(REMOVE_ITEM apps ${CMAKE_CURRENT_SOURCE_DIR}/bpf/profile.bpf.c)
endif()

# 4.设置并创建  <>/src-gen/TOOL_BELONG_TO_MODULE/TOOL_NAME 文件夹
set(SRC_GEN_TARGET_DIR ${CONFIG_SRC_GEN_DIR}/${TOOL_BELONG_TO_MODULE}/${TOOL_NAME})
if (NOT EXISTS ${SRC_GEN_TARGET_DIR})
    file(MAKE_DIRECTORY ${SRC_GEN_TARGET_DIR})
    message(STATUS "directory create success")
endif ()

# 5.遍历文件夹内所有的bpf.c
foreach(app ${apps})
    get_filename_component(app_stem ${app} NAME_WE)# 获取子工具文件的名字，并保存在app_stem中
    # Build object skeleton and depend skeleton on libbpf build
    bpf_object(${app_stem} ${app_stem}.bpf.c ${SRC_GEN_TARGET_DIR})# 生成骨架文件并放在SRC_GEN_TARGET_DIR目录
    add_dependencies(${app_stem}_skel libbpf-build bpftool-build)# 每个生成的骨架文件都依赖于 libbpf 和 bpftool，这两个工具是 eBPF 开发的基础
endforeach()
# 6.创建可执行文件 cpuwatcher & controller
add_executable(${TOOL_NAME} src/${TOOL_NAME}.c)
add_executable(${CONTROLLER_NAME} src/${CONTROLLER_NAME}.c)
# 7.链接骨架文件到cpuwatcher
foreach (app ${apps})
    get_filename_component(app_stem ${app} NAME_WE)
    target_link_libraries(${TOOL_NAME} ${app_stem}_skel)# 将子工具生成的骨架文件链接到cpuwatcher中
    # 对于rust情况
    if(${app_stem} STREQUAL "profile")
        target_include_directories(${app_stem} PRIVATE
                ${CMAKE_SOURCE_DIR}/blazesym/include)
        target_link_libraries(${app_stem}
                ${CMAKE_SOURCE_DIR}/blazesym/target/release/libblazesym.a -lpthread -lrt -ldl)
    endif()
endforeach ()
# 8.controller链接到
target_link_libraries(${CONTROLLER_NAME} PRIVATE ${LIBBPF_LIBRARIES} pthread rt dl)
target_link_libraries(${CONTROLLER_NAME} PRIVATE elf z)

# 将可执行文件，配置文件等安装在对应的位置
# 设置安装目录
set(CPU_WATCHER_INSTALL_DIR backend/${TOOL_BELONG_TO_MODULE}/${TOOL_NAME})
# 安装可执行文件到 ${CPU_WATCHER_INSTALL_DIR}/bin
install(TARGETS ${TOOL_NAME}
        RUNTIME DESTINATION ${CPU_WATCHER_INSTALL_DIR}/bin)
install(TARGETS ${CONTROLLER_NAME}
        RUNTIME DESTINATION ${CPU_WATCHER_INSTALL_DIR}/bin)
# 安装配置文件到 ${CPU_WATCHER_INSTALL_DIR}/etc