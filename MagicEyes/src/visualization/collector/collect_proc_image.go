// Copyright 2023 The LMP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// author: Gui-Yue
//
// 为proc_image所适配的collector，实现对proc_image输出格式的支持。

package collector

import (
	"bufio"
	"visualization/checker"
	"visualization/dao"
	"visualization/prom_core"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v2"
)

// Pro_Setting 定义了设置项，通过读取同目录下的tmux_proc_setting.yaml实现对基本信息的设置。
type Proc_Setting struct {
	Name        string `yaml:"proc_name"`
	Path        string `yaml:"proc_path"`
	Pid         string `yaml:"proc_pid"`
	Max_Records int    `yaml:"proc_max_records"`
}

// 定义了一个名为 proc_imageCommand 的 CLI 命令，用于执行特定的数据收集任务
var proc_imageCommand = cli.Command{
	Name: "proc_image",
	// 设置命令的别名，即用户可以使用 "pro" 作为缩写形式来调用相同的命令
	Aliases: []string{"pro"},
	Usage:   "Special collect data out from proc_image",
	// 设置命令执行时调用的函数为 procCollect
	Action: procCollect,
}

// Get_Setting 函数用于获取设置的信息，返回一个错误、命令字符串和最大记录数
func Get_Setting(which string) (error, string, int) {
	// 获取当前工作目录的绝对路径
	currentDir, _ := os.Getwd()
	// 读取配置文件 tmux_proc_setting.yaml 的内容
	content, err := os.ReadFile(currentDir + "/collector/tmux_proc_setting.yaml")
	// 如果读取配置文件时发生错误，输出错误信息并返回错误
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
		return err, "", 0
	}
	command := ""
	maxrecords := 0
	if which == "proc" {
		// 声明一个 Proc_Setting 类型的变量 setting，用于存储从配置文件解析得到的设置
		var setting Proc_Setting
		// 使用 YAML 解码器将配置文件内容解析到 setting 变量中
		err = yaml.Unmarshal(content, &setting)
		// 如果解码时发生错误，输出错误信息并返回错误
		if err != nil {
			log.Fatalf("Error unmarshaling YAML :%v", err)
			return err, "", 0
		}

		// 构造命令字符串，包括路径和进程 ID
		command = setting.Path + " -p " + setting.Pid
		// 获取最大记录数
		maxrecords = setting.Max_Records
	} else if which == "tmux" {
		var setting Tmux_Setting
		err = yaml.Unmarshal(content, &setting)
		if err != nil {
			log.Fatalf("Error unmarshaling YAML :%v", err)
			return err, "", 0
		}

		command = setting.Path + " -p " + setting.Pid
		maxrecords = setting.Max_Records
	} else {
		log.Fatalf("select setting failed.")
	}
	return nil, command, maxrecords
}

func procCollect(ctx *cli.Context) error {
	// 调用 Get_Setting 函数获取 "proc" 类型的设置信息，其中 _ 表示占位符，因为 Get_Setting 返回三个值，但当前只关心 command
	_, command, _ := Get_Setting("proc")
	return ProcRun(command)
}

// ProcRun 是收集器的主函数，通过goroutin的方式实现数据收集，重定向，与prom_core包实现通信。
// 该函数接收一个字符串参数 command，表示要执行的命令
func ProcRun(command string) error {
	// 检查文件类型，并将检查后的命令字符串存储在 cmdStr 变量中
	_, cmdStr := CheckFileType(command)
	// 创建一个表示将要执行的命令的对象，并将其赋值给 cmd 变量
	cmd := exec.Command("sh", "-c", cmdStr)

	// 设置进程组 ID
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// 获取命令的标准输出管道
	stdout, err := cmd.StdoutPipe()
	// 输出完整的执行命令，方便调试
	log.Println("full command is :", cmdStr)
	if err != nil {
		log.Println("get stdout failed:", err)
	}

	// 启动一个 goroutine 监听系统信号
	go listenSystemSignals(cmd)

	// 创建一个带有缓冲区的通道，用于在 goroutine 之间传递 map 类型的数据
	mapchan := make(chan map[string]interface{}, 2)

	loc, _ := time.LoadLocation("Asia/Shanghai")
	// 获取当前时间，并将其转换为浮点数格式
	currenttime := float64(time.Now().In(loc).UnixNano()) / 1e9

	// 将命令字符串按 "/" 分割成字符串切片
	pathlist := strings.Split(command, "/")
	// 使用正则表达式判断命令中是否包含 "proc"
	is_proc, _ := regexp.MatchString(`proc`, pathlist[len(pathlist)-1])
	// 使用正则表达式判断命令中是否包含 "lifecycle"
	is_lifecycle, _ := regexp.MatchString(`lifecycle`, pathlist[len(pathlist)-1])
	// 使用正则表达式判断命令中是否包含 "lock"
	is_lock, _ := regexp.MatchString(`lock`, pathlist[len(pathlist)-1])

	if is_proc || is_lifecycle {
		log.Println("This is lifecycle")
		_, _, maxrecords := Get_Setting("proc")
		// 启动 goroutine，将命令的标准输出传递给 mapchan
		go redirectProc(stdout, mapchan)

		// 创建 prom_core.ProcMetrics 类型的变量 procdata，用于存储从 "proc" 类型的命令中收集到的数据
		procdata := prom_core.ProcMetrics{Max_records: maxrecords, NowTime: currenttime}
		// 创建 dao.Sqlobj 类型的变量 sqlobj，用于与数据库交互，设置表名为 "proc_image_data"
		sqlobj := &dao.Sqlobj{Tablename: "proc_image_data"}
		procdata.Sqlobj = sqlobj
		// 启动 goroutine，初始化并运行 procdata 中的数据处理服务
		go procdata.BootProcService()

		//  启动匿名 goroutine，用于处理从 mapchan 接收到的数据并进行相应的操作，如更新数据库
		go func() {
			for {
				select {
				case <-mapchan:
					procdata.Getorigindata(mapchan)
					if procdata.Sqlinted {
						procdata.UpdateSql()
					} else {
						procdata.Initsql()
					}
					procdata.UpdateRecords()
					<-mapchan
				default:
				}
			}
		}()

	} else if is_lock {
		log.Println("This is lock_image.")
		_, _, maxrecords := Get_Setting("tmux")
		go redirectTmux(stdout, mapchan)
		tmuxdata := prom_core.TmuxMetrics{Max_records: maxrecords, NowTime: currenttime}
		sqlobj := &dao.Sqlobj{Tablename: "tmux_data"}
		tmuxdata.Sqlobj = sqlobj
		go tmuxdata.BootProcService()
		go func() {
			for {
				select {
				case <-mapchan:
					tmuxdata.Getorigindata(mapchan)
					if tmuxdata.Sqlinted {
						tmuxdata.UpdateSql()
					} else {
						tmuxdata.Initsql()
					}
					tmuxdata.UpdateRecords()
					<-mapchan
				default:
				}
			}
		}()
	}

	// 启动命令，如果启动失败，则输出错误信息并退出程序
	err = cmd.Start()
	if err != nil {
		log.Printf("cmd.Start() analysis service failed: %v", err)
		os.Exit(-1)
	}

	// 等待命令执行完成，如果执行失败，则输出错误信息并退出程序
	err = cmd.Wait()
	if err != nil {
		log.Printf("cmd.Run() analysis failed with: %v", err)
		os.Exit(-1)
	}

	return nil
}

// redirectProc 实现数据重定向
// stdout 表示命令的标准输出流，mapchan 表示用于传递数据的通道
func redirectProc(stdout io.ReadCloser, mapchan chan map[string]interface{}) {
	// 声明一个 map 类型的变量 onemap，用于存储从命令的标准输出中解析出的数据
	var onemap map[string]interface{}
	// 使用 bufio.NewScanner 创建一个扫描器，用于逐行扫描命令的标准输出
	scanner := bufio.NewScanner(stdout)
	// 循环读取命令的标准输出的每一行
	for scanner.Scan() {
		// 获取当前行的文本内容
		line := scanner.Text()
		// 去除行中的不必要空格
		line = checker.CutunexceptedSpace(line)
		// 判断当前行是否是 "proc" 命令的输出
		if checker.IsProcOutput(line) {
			// 创建一个新的 map 对象，用于存储该行数据
			onemap = make(map[string]interface{})
			// 将当前行按空格分割成字符串切片，每个元素表示一组键值对
			parms := strings.Fields(line)
			// 循环处理每个键值对
			for _, value := range parms {
				// 将键值对按冒号分割成键和值
				parts := strings.Split(value, ":")
				// 将键值对存储到 onemap 中
				onemap[parts[0]] = parts[1]
			}
			// log.Println(onemap)
			// 将存储了当前行数据的 onemap 发送到 mapchan 通道中，以便后续处理
			mapchan <- onemap
			// 如果不是 "proc" 命令的输出，则继续下一轮循环
		} else {
			continue
		}
	}
}
