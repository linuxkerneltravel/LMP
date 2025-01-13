# 设置最低 CMake 版本要求
cmake_minimum_required(VERSION 3.10)

# 定义项目名称
project(DataVisual LANGUAGES NONE)

# 定义工作目录变量
set(WORK_DIR "${CMAKE_BINARY_DIR}/src/visualization")

# 确保工作目录存在
file(MAKE_DIRECTORY ${WORK_DIR})

# 直接执行命令：go mod tidy
execute_process(
    COMMAND go mod tidy
    WORKING_DIRECTORY ${WORK_DIR}  # 设置工作目录为 ${CMAKE_BINARY_DIR}/data-visual
    RESULT_VARIABLE GO_MOD_TIDY_RESULT
    OUTPUT_VARIABLE GO_MOD_TIDY_OUTPUT
    ERROR_VARIABLE GO_MOD_TIDY_ERROR
)
if(NOT GO_MOD_TIDY_RESULT EQUAL 0)
    message(FATAL_ERROR "Failed to run 'go mod tidy': ${GO_MOD_TIDY_ERROR}")
endif()

# 直接执行命令：go build
execute_process(
    COMMAND go build -o ${WORK_DIR}/data-visual main.go
    WORKING_DIRECTORY ${WORK_DIR}
    RESULT_VARIABLE GO_BUILD_RESULT
    OUTPUT_VARIABLE GO_BUILD_OUTPUT
    ERROR_VARIABLE GO_BUILD_ERROR
)
if(NOT GO_BUILD_RESULT EQUAL 0)
    message(FATAL_ERROR "Failed to build 'data-visual': ${GO_BUILD_ERROR}")
endif()

# 创建目录并生成文件
file(MAKE_DIRECTORY ${WORK_DIR}/.output/data)
file(WRITE ${WORK_DIR}/.output/data/offcpu_stack.txt "")

# 直接执行脚本：runimages.sh
execute_process(
    COMMAND ./runimages.sh
    WORKING_DIRECTORY ${WORK_DIR}
    RESULT_VARIABLE RUN_IMAGES_RESULT
    OUTPUT_VARIABLE RUN_IMAGES_OUTPUT
    ERROR_VARIABLE RUN_IMAGES_ERROR
)
if(NOT RUN_IMAGES_RESULT EQUAL 0)
    message(FATAL_ERROR "Failed to run 'runimages.sh': ${RUN_IMAGES_ERROR}")
endif()

# 清理目标：可选
add_custom_target(clean_data
    COMMAND ${CMAKE_COMMAND} -E rm -rf ${WORK_DIR}/dao/data.db ${WORK_DIR}/.output/data
    COMMENT "Cleaning up generated data and files"
)
