#!/bin/bash

# 挂载点目录
MOUNT_POINT="../src/mountpoints"
SRC_DIR="../src"

# FUSE 可执行文件
FUSE_EXEC="../src/difuse"

echo "Compiling FUSE filesystem..."
make -C "$SRC_DIR" clean
make -C "$SRC_DIR" all

# 检查编译是否成功
if [ ! -f "$FUSE_EXEC" ]; then
    echo "Compilation failed. Exiting."
    exit 1
fi

# 创建挂载点目录（如果不存在）
if [ ! -d "$MOUNT_POINT" ]; then
    mkdir -p "$MOUNT_POINT"
fi

# 挂载 FUSE 文件系统（前台运行并显示调试信息）
echo "Mounting FUSE filesystem..."
$FUSE_EXEC -f -d "$MOUNT_POINT" &
FUSE_PID=$!
sleep 2  # 等待文件系统完全挂载

# 确保脚本退出时卸载文件系统
trap "fusermount -u $MOUNT_POINT" EXIT

# 基准测试：写入
echo "开始写入基准测试..."
echo "# Write operation: Creating testfile_100MB_1" >> ../test/dd_output.log
dd if=/dev/zero of=$MOUNT_POINT/testfile_100MB_1 bs=1M count=100 status=progress 2>> ../test/dd_output.log
echo "Created testfile_100MB_1"

# 读取
echo "# Read operation: Reading testfile_100MB_1" >> ../test/dd_output.log
dd if=$MOUNT_POINT/testfile_100MB_1 of=/dev/null bs=1M status=progress 2>> ../test/dd_output.log
echo "Read testfile_100MB_1"
