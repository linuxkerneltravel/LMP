# 设置最低 CMake 版本要求
cmake_minimum_required(VERSION 3.10)

# 定义项目名称
project(DataVisual LANGUAGES NONE)
#目标目录,install/visualization
set(VISUALIZATION_INSTALL_DIR visualization)
# 定义变量 A
set(EBPF_PROMETHEUS ${CMAKE_CURRENT_SOURCE_DIR}/eBPF_prometheus)


# 直接执行命令：go mod tidy
execute_process(
    COMMAND go mod tidy
    WORKING_DIRECTORY ${EBPF_PROMETHEUS}
    RESULT_VARIABLE GO_MOD_TIDY_RESULT
    OUTPUT_VARIABLE GO_MOD_TIDY_OUTPUT
    ERROR_VARIABLE GO_MOD_TIDY_ERROR
)
if(NOT GO_MOD_TIDY_RESULT EQUAL 0)
    message(FATAL_ERROR "Failed to run 'go mod tidy': ${GO_MOD_TIDY_ERROR}")
endif()

# 直接执行命令：go build
execute_process(
    COMMAND go build -o ${EBPF_PROMETHEUS}/data-visual main.go
    WORKING_DIRECTORY ${EBPF_PROMETHEUS}
    RESULT_VARIABLE GO_BUILD_RESULT
    OUTPUT_VARIABLE GO_BUILD_OUTPUT
    ERROR_VARIABLE GO_BUILD_ERROR
)
if(NOT GO_BUILD_RESULT EQUAL 0)
    message(FATAL_ERROR "Failed to build 'data-visual': ${GO_BUILD_ERROR}")
endif()
#将生成的data-visual可执行文件 安装到install/visualization目录下
install(PROGRAMS ${EBPF_PROMETHEUS}/data-visual
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ WORLD_READ WORLD_EXECUTE
        DESTINATION ${VISUALIZATION_INSTALL_DIR}
)
#将checker,collector,dao,prom_core安装到安装到install/visualization目录下
install(DIRECTORY ${EBPF_PROMETHEUS}/checker
                ${EBPF_PROMETHEUS}/dao
                ${EBPF_PROMETHEUS}/prom_core
        DESTINATION ${VISUALIZATION_INSTALL_DIR}
)
# 创建目录并生成文件
file(MAKE_DIRECTORY ${VISUALIZATION_INSTALL_DIR}/.output/data)
file(WRITE ${VISUALIZATION_INSTALL_DIR}/.output/data/offcpu_stack.txt "")


# 安装脚本文件 runimages.sh 到指定目录，并设置安装后的权限
install(PROGRAMS ${EBPF_PROMETHEUS}/runimages.sh
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ WORLD_READ WORLD_EXECUTE
        DESTINATION ${VISUALIZATION_INSTALL_DIR}
)
# 执行脚本：runimages.sh
execute_process(
    COMMAND ./runimages.sh
    WORKING_DIRECTORY ${VISUALIZATION_INSTALL_DIR}
    RESULT_VARIABLE RUNIMAGES_RESULT
    OUTPUT_VARIABLE RUNIMAGES_OUTPUT
    ERROR_VARIABLE RUNIMAGES_ERROR
)
# 将vis.sh安装到目标目录
install(PROGRAMS ${EBPF_PROMETHEUS}/vis.sh
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ WORLD_READ WORLD_EXECUTE
        DESTINATION ${VISUALIZATION_INSTALL_DIR}
)

# 清理目标：可选
add_custom_target(clean_data
    COMMAND ${CMAKE_COMMAND} -E rm -rf ${EBPF_PROMETHEUS}/dao/data.db ${EBPF_PROMETHEUS}/r/.output/data
    COMMENT "Cleaning up generated data and files"
)
