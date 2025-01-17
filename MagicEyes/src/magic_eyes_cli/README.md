## magic_eyes_cli 命令行前端

### 1. 简述

将所有的后端工具统一到一个命令行前端，并且具备自动补全功能。

Tips：**记得Tab**

### 2. 使用之前

```bash
mkdir build && cd build
cmake .. && make && make install
cd ./install/magic_eyes_cli
# 运行前置条件脚本
source ./before_running.sh
```
#### 2.1 遇到问题
这里可能会由于虚拟环境没有建立而产生一个问题：
```bash
python 已安装
bash: ./venv/bin/activate:没有那个文件或目录
进入venv环境失败
条件不满足
```
这是由于在`before_running.sh`脚本文件中存在以下环境判断而导致的报错：
```bash
	# 进入python venv环境
	if . ./venv/bin/activate; then
		echo "成功进入venv环境"
	else
		echo "进入venv环境失败"
		return 1
	fi
```

我们需要配置相关虚拟环境，即安装venv模块：

```bash
sudo apt install python3-venv 
```

安装成功之后，便可通过以下命令在lmp/MagicEyes/build/install/magic_eyes_cli目录下创建虚拟环境：
```bash
python3 -m venv venv
```
这时再运行`source ./before_running.sh`脚本便可通过。

### 3. 使用

```bash
(venv) $ ./magic_eyes_cli -h
/home/fzy/Downloads/04_bcc_ebpf/MagicEyes
usage: magic_eyes_cli [-h] [-l | -c] {net,memory,system_diagnosis,process} ...

magic_eyes_cli: command tools for Linux kernel diagnosis and optimization

positional arguments:
  {net,memory,system_diagnosis,process}
    net                 tool for Linux net subsystem
    memory              tool for Linux memory subsystem
    system_diagnosis    tool for Linux system_diagnosis subsystem
    process             tool for Linux process subsystem

optional arguments:
  -h, --help            show this help message and exit

all of common options:
  -l                    list all avaliable tools
  -c                    check all tools dependency, and whether it can be run in current platform

eg: magic_eyes_cli -l
```

**固定命令**

magic_eyes_cli具有2个固定命令， 即

```bash
-l : 即list， 列出所有可用的后端命令
-c : 即check， 检查所有运行依赖项（暂未实现）
```

**动态命令**

{net,memory,system_diagnosis,process}为动态命令，会根据backend文件夹下的情况动态调整。

### 4. 例程

```bash
./magic_eyes_cli process cpu_watcher -h
# <------------------ 自动补全 | 非自动补全
```

### 5.其他

```bash
# 生成requirements.txt
pip3 freeze > requirements.txt
#  安装
pip3 install -r requiredments.txt
```
