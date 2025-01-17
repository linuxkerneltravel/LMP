#!/bin/bash

# 检查参数数量是否足够
if [ $# -lt 4 ]; then
  echo "Usage: $0 <param1> <param2> <param3> <param4> [other_args...]"
  exit 1
fi

# 获取传递的参数
PARAM1=$1
PARAM2=$2
PARAM3=$3
PARAM4=$4
OTHER_ARGS=${@:5} # 从第5个参数开始的所有额外参数

# 构建路径
TARGET_DIR="../backend/${PARAM1}/${PARAM2}/bin"

# 构建命令
COMMAND="sudo ./data-visual collect ${TARGET_DIR}/${PARAM3} ${PARAM4} ${OTHER_ARGS}"

# 显示即将执行的命令（可选）
echo "Executing command: ${COMMAND}"

# 执行命令
eval "${COMMAND}"
