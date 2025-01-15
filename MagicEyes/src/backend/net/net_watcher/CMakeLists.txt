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
#      net_watcher 工具 CMakeLists 文件
# -----------------------------------------------------------------------------------------
set(TOOL_NAME net_watcher)
set(TOOL_BELONG_TO_MODULE net)

file(GLOB apps ${CMAKE_CURRENT_SOURCE_DIR}/bpf/*.bpf.c)
# 若不用Rust，则排除 profile.bpf.c
if(NOT CARGO_EXISTS)
    list(REMOVE_ITEM apps ${CMAKE_CURRENT_SOURCE_DIR}/bpf/profile.bpf.c)
endif()

# 设置并创建  <>/src-gen/TOOL_BELONG_TO_MODULE/TOOL_NAME 文件夹
set(SRC_GEN_TARGET_DIR ${CONFIG_SRC_GEN_DIR}/${TOOL_BELONG_TO_MODULE}/${TOOL_NAME})
if (NOT EXISTS ${SRC_GEN_TARGET_DIR})
    file(MAKE_DIRECTORY ${SRC_GEN_TARGET_DIR})
    message(STATUS "directory create success")
endif ()

# 遍历文件夹内所有的bpf.c
foreach(app ${apps})
    get_filename_component(app_stem ${app} NAME_WE)
    # Build object skeleton and depend skeleton on libbpf build
    bpf_object(${app_stem} ${app_stem}.bpf.c ${SRC_GEN_TARGET_DIR})
    add_dependencies(${app_stem}_skel libbpf-build bpftool-build)
endforeach()

# add_executable(${TOOL_NAME} src/${TOOL_NAME}.c)
add_executable(${TOOL_NAME} 
    src/${TOOL_NAME}.c 
    src/net_watcher_hepler.c 
)
foreach (app ${apps})
    get_filename_component(app_stem ${app} NAME_WE)
    target_link_libraries(${TOOL_NAME} ${app_stem}_skel)

    if(${app_stem} STREQUAL "profile")
        target_include_directories(${app_stem} PRIVATE
                ${CMAKE_SOURCE_DIR}/blazesym/include)
        target_link_libraries(${app_stem}
                ${CMAKE_SOURCE_DIR}/blazesym/target/release/libblazesym.a -lpthread -lrt -ldl)
    endif()
endforeach ()

# 将可执行文件，配置文件等安装在对应的位置
# 设置安装目录
set(CPU_WATCHER_INSTALL_DIR backend/${TOOL_BELONG_TO_MODULE}/${TOOL_NAME})
# 安装可执行文件到 ${CPU_WATCHER_INSTALL_DIR}/bin
install(TARGETS ${TOOL_NAME}
        RUNTIME DESTINATION ${CPU_WATCHER_INSTALL_DIR}/bin)
# 安装配置文件到 ${CPU_WATCHER_INSTALL_DIR}/etc
# 获取内核版本
execute_process(
    COMMAND uname -r
    OUTPUT_VARIABLE VERSION_INFO
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

# 使用'-'分隔版本
string(REPLACE "-" ";" VERSION_PARTS ${VERSION_INFO})
list(GET VERSION_PARTS 0 VERSION_BASE)

# 从VERSION_BASE中提取主、次和补丁版本
string(REPLACE "." ";" VERSION_NUMBERS ${VERSION_BASE})
list(GET VERSION_NUMBERS 0 VERSION_MAJOR)
list(GET VERSION_NUMBERS 1 VERSION_MINOR)
list(GET VERSION_NUMBERS 2 VERSION_PATCH)

message(STATUS "Kernel Major: ${VERSION_MAJOR}, Minor: ${VERSION_MINOR}, Patch: ${VERSION_PATCH}")

set(MIN_VERSION_MAJOR 6)
set(MIN_VERSION_MINOR 4)

if(MAJOR GREATER MIN_VERSION_MAJOR OR (MAJOR EQUAL MIN_VERSION_MAJOR AND MINOR GREATER_EQUAL MIN_VERSION_MINOR))
    add_definitions(-DUSE_NEW_GET_USER_DATA)  
else()
    add_definitions(-DUSE_OLD_GET_USER_DATA)   
endif()


