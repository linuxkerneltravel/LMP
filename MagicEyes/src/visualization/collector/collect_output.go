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
// 该文件用于将收集到的信息进行进行规范化处理，实现重定向，并与Prometheus可视化逻辑进行交互。

package collector

import (
	"bufio"
	"visualization/checker"
	"visualization/dao"
	"visualization/prom_core"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/urfave/cli/v2"
)

const firstline = int(1)

// 定义了一个结构体类型 Aservice
type Aservice struct {
	// 服务的名称
	Name string
	// 服务的描述
	Desc string
	// NewInst 是一个函数类型的字段，用于创建服务实例
	// 当一个函数返回 interface{} 类型时，它实际上是在表示该函数可以返回任何类型的值。
	// 在使用这样的设计时，调用方可能需要使用类型断言来将 interface{} 类型的服务实例转换为具体的类型，以便进行后续的操作。
	NewInst func(ctx *cli.Context, opts ...interface{}) (interface{}, error)
}

// 定义了一个名为 GlobalServices 的变量，它是一个结构体类型的值
var GlobalServices = struct {
	// 使用 sync.RWMutex 类型的嵌入字段，提供读写锁功能
	sync.RWMutex
	// services 是一个 map，键是字符串类型，值是指向 Aservice 结构体的指针
	services map[string]*Aservice
}{}

func AddAService(svc *Aservice) error {
	GlobalServices.Lock()
	defer GlobalServices.Unlock()

	if _, existed := GlobalServices.services[svc.Name]; existed {
		return fmt.Errorf("service existed: %s", svc.Name)
	}

	GlobalServices.services[svc.Name] = svc

	return nil
}

// 定义一个名为 RunServices 的函数，接受一个回调函数作为参数
func RunServices(fn func(nm string, svc *Aservice) error) error {
	// 对全局服务列表进行加锁
	GlobalServices.Lock()
	// 在函数结束时解锁，确保解锁操作一定会执行
	defer GlobalServices.Unlock()

	// 遍历全局服务列表中的服务
	// name 是服务的名称，service 是服务实例
	for name, service := range GlobalServices.services {
		// 调用传入的回调函数，并传递服务名称和服务实例作为参数
		if err := fn(name, service); err != nil {
			// 如果回调函数返回错误，立即返回该错误
			return err
		}
	}
	// 如果遍历完所有服务都没有发生错误，返回 nil 表示成功
	return nil
}

// 定义一个名为 collectCommand 的 cli.Command 类型变量
var collectCommand = cli.Command{
	// 设置命令的名称
	Name: "collect",
	// 设置命令的别名（可以使用 "c" 作为别名）
	Aliases: []string{"c"},
	// 设置命令的用途描述
	Usage: "collect system data by eBPF",
	// 设置命令执行时调用的处理函数（Action）
	Action: simpleCollect,
}

// init 函数在包被导入时自动执行
func init() {
	// 初始化全局服务列表的 services 字段，使用 make 创建一个空的 map
	GlobalServices.services = make(map[string]*Aservice)

	// 创建并配置一个名为 "collectData" 的服务实例
	svc := Aservice{
		Name:    "collectData",
		Desc:    "collect eBPF data",
		NewInst: newCollectCmd, // 指定该服务的 NewInst 方法为 newCollectCmd
	}

	// 将服务实例添加到全局服务列表
	if err := AddAService(&svc); err != nil {
		log.Fatalf("Failed to load ... error:%s\n", err)
		return
	}

	// 创建并配置一个名为 "procCollectData" 的服务实例
	procSvc := Aservice{
		Name:    "procCollectData",
		Desc:    "collect process eBPF data",
		NewInst: newProcCmd, // 指定该服务的 NewInst 方法为 newProcCmd
	}

	// 将服务实例添加到全局服务列表
	if err := AddAService(&procSvc); err != nil {
		log.Fatalf("Failed to load ... error:%s\n", err)
		return
	}

	// 创建并配置一个名为 "tmuxCollectData" 的服务实例
	tmuxSvc := Aservice{
		Name:    "tmuxCollectData",
		Desc:    "collect data from lock_image",
		NewInst: newTmuxCmd, // 指定该服务的 NewInst 方法为 newTmuxCmd
	}

	// 将服务实例添加到全局服务列表
	if err := AddAService(&tmuxSvc); err != nil {
		log.Fatalf("Failed to load ... error:%s\n", err)
		return
	}
}

func newCollectCmd(ctx *cli.Context, opts ...interface{}) (interface{}, error) {
	return collectCommand, nil
}

func newProcCmd(ctx *cli.Context, opts ...interface{}) (interface{}, error) {
	return proc_imageCommand, nil
}

func newTmuxCmd(ctx *cli.Context, opts ...interface{}) (interface{}, error) {
	return tmux_command, nil
}

// 定义了一个名为 BPF_name 的结构体
type BPF_name struct {
	// 结构体包含一个字段 Name，表示 BPF 名称
	Name string
}

// 定义了一个名为 simpleCollect 的函数，用于执行简单的收集操作
func simpleCollect(ctx *cli.Context) error {
	// 调用 CollectCheck 函数，检查并获取完整的命令行参数
	full, err := checker.CollectCheck(ctx)
	if err != nil {
		// 如果出现错误，直接返回错误
		return err
	}

	// 使用 strings.Fields 将完整的命令行参数拆分成字段，并取第一个字段作为路径
	path := strings.Fields(full)[0]

	// 使用 strings.Split 将路径按 "/" 分割成切片
	pathlist := strings.Split(path, "/")

	// 创建 BPF_name 结构体实例，并将其 Name 字段初始化为处理过的文件名，去除了文件名中的 ".py" 后缀，表示收集操作的名称
	n := BPF_name{Name: strings.ReplaceAll(pathlist[len(pathlist)-1], ".py", "")}

	// 调用 BPF_name 结构体的 Run 方法执行收集操作
	return n.Run(full)
}

// 定义了一个名为 CheckFileType 的函数，用于检查文件类型并返回相应的命令字符串
func CheckFileType(full string) (filename, specificcommand string) {
	// 创建一个字符串切片，用于构建命令
	cmdSlice := make([]string, 0)
	// 将 "sudo" 添加到命令切片
	cmdSlice = append(cmdSlice, "sudo")
	// stdbuf -oL 表示将标准输出设置为行缓冲模式。这样可以使得输出更及时地显示在终端上，而不会等到缓冲区满或遇到换行符才刷新
	// 将 "stdbuf" 添加到命令切片
	cmdSlice = append(cmdSlice, "stdbuf")
	// 将 "-oL" 添加到命令切片，这是为了调整输出缓冲方式
	cmdSlice = append(cmdSlice, "-oL")
	// 使用 strings.Fields 将完整的命令行参数拆分成字段，并取第一个字段作为路径
	path := strings.Fields(full)[0]
	// 将文件路径转换为小写
	lowercaseFilename := strings.ToLower(path)
	// 获取文件名
	fn := filepath.Base(lowercaseFilename)
	// 如果文件路径以 ".py" 结尾
	if strings.HasSuffix(lowercaseFilename, ".py") {
		// 打印日志，表示尝试运行一个 Python 程序
		log.Println("Try to run a BCC program.")
		// 将 "python3" 添加到命令切片
		cmdSlice = append(cmdSlice, "python3")
		// 将 "-u" 添加到命令切片，表示无缓冲输出
		cmdSlice = append(cmdSlice, "-u")
		// 将输入的命令添加到命令切片
		cmdSlice = append(cmdSlice, full)
		// 使用空格连接命令切片，形成完整的命令字符串
		cmdStr := strings.Join(cmdSlice, " ")
		// 返回构建好的命令字符串
		return fn, cmdStr
	} else {
		// 如果不是以 ".py" 结尾
		// 打印日志，表示尝试运行一个 eBPF 程序
		log.Println("Try to run a libbpf program.")
		// 将 "-u" 添加到命令切片，表示无缓冲输出
		// cmdSlice = append(cmdSlice, "-u")
		// 将文件路径添加到命令切片
		cmdSlice = append(cmdSlice, full)
		// 使用空格连接命令切片，形成完整的命令字符串
		cmdStr := strings.Join(cmdSlice, " ")
		// 返回构建好的命令字符串
		return fn, cmdStr
	}
}

// 定义了一个名为 Run 的方法，属于 BPF_name 结构体
func (b *BPF_name) Run(full string) error {
	// 检查文件类型，获取相应的命令字符串
	fn, cmdStr := CheckFileType(full)
	// 创建一个执行外部命令的 Command 对象
	// -c 表示后面的参数是一个命令字符串，而不是一个可执行文件
	cmd := exec.Command("sh", "-c", cmdStr)

	// 设置 SysProcAttr，用于设置新创建的进程的属性
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// 获取命令的标准输出管道
	stdout, err := cmd.StdoutPipe()
	log.Println("full command is :", cmdStr)
	if err != nil {
		log.Println("get stdout failed:", err)
	}

	// 启动一个 goroutine 监听系统信号
	go listenSystemSignals(cmd)
	//go getStdout(stdout)

	// 创建一个用于传递 map 数据的通道
	mapchan := make(chan []map[string]interface{}, 2)

	// 启动一个 goroutine 用于重定向命令的标准输出
	go redirectStdout(fn, stdout, mapchan)

	// 创建一个指向 prom_core.MyMetrics 类型的指针 metricsobj，
	// 并使用结构体字段初始化 BPFName 和 Sqlinited。
	metricsobj := &prom_core.MyMetrics{BPFName: b.Name, Sqlinited: false}

	// 创建一个指向 dao.Sqlobj 类型的指针 sqlobj，
	// 并使用结构体字段初始化 Tablename。
	sqlobj := &dao.Sqlobj{Tablename: b.Name}
	metricsobj.Sqlobj = sqlobj

	// 启动 MyMetrics 实例的服务
	go metricsobj.StartService()

	// 启动一个 goroutine 处理从重定向标准输出通道收到的数据
	go func() {
		for {
			select {
			// 当从通道中接收到数据时
			case <-mapchan:
				// 从通道中获取 map 切片，将其赋值给 MyMetrics 实例的 Maplist 字段
				metricsobj.Maplist = <-mapchan
				log.Println(metricsobj.Maplist)
				// 更新 MyMetrics 实例的数据
				metricsobj.UpdateData()
				// 如果 SQL 已初始化，则更新 SQL 数据；否则，初始化 SQL
				if metricsobj.Sqlinited {
					metricsobj.UpdataSql(fn)
				} else {
					metricsobj.Initsql(fn)
				}
				// 从通道中接收第二次数据
				<-mapchan
			default:
			}
		}
	}()

	// 启动命令
	err = cmd.Start()
	if err != nil {
		log.Printf("cmd.Start() analysis service failed: %v", err)
		os.Exit(-1)
	}

	// 等待命令执行完毕
	err = cmd.Wait()
	if err != nil {
		log.Printf("cmd.Run() analysis failed with: %v", err)
		os.Exit(-1)
	}

	return nil
}

// 定义了一个名为 listenSystemSignals 的函数，用于监听系统信号
func listenSystemSignals(cmd *exec.Cmd) {
	// 创建一个用于接收系统信号的通道
	signalChan := make(chan os.Signal, 1)

	// 向 signalChan 注册接收的系统信号类型，包括 Interrupt、Kill 和 SIGTERM
	signal.Notify(signalChan, os.Interrupt, os.Kill, syscall.SIGTERM)

	// 无限循环，等待接收系统信号
	for {
		select {
		// 当从 signalChan 中接收到信号时
		case <-signalChan:
			// 向指定进程组发送 SIGKILL 信号，结束进程
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)

			// 退出当前程序，返回状态码 1
			os.Exit(1)
		}
	}
}

// 定义了一个名为 redirectStdout 的函数，用于读取 stdout，并将其解析成 map 数据发送到指定通道
func redirectStdout(fn string, stdout io.ReadCloser, mapchan chan []map[string]interface{}) {
	// 用于存储解析后的 map 数据的切片
	var maps []map[string]interface{}
	// 互斥锁，用于保护 maps 切片的并发写入
	var mu sync.Mutex
	// 创建一个 bufio.Scanner 用于逐行读取 stdout 的内容
	scanner := bufio.NewScanner(stdout)
	// 存储标题的字符串切片
	var titles []string
	var rsc_titles []string
	var sched_titles []string
	var syscall_titles []string
	var ulock_titles []string
	var kt_titles []string

	// 行号计数器
	var line_number = 1
	// 命令索引，用于区分不同的命令
	var commandindex = 0

	// RESOURCE(1)、SCHEDULE(2)、SYSCALL(3)、USERLOCK(4)、KEYTIME(5)
	var data_type = 0
	var set_map = 0
	var enable_tgid = 0
	// 1 代表已创建表头
	data_map := [6]int{0, 0, 0, 0, 0, 0}

	rsc_pidheader := make(map[int][]string)
	sched_pidheader := make(map[int][]string)
	syscall_pidheader := make(map[int][]string)
	ulock_pidheader := make(map[int][]string)
	kt_pidheader := make(map[int][]string)

	var pid int
	var err error

	// proc_image
	// 判断程序名是否为 proc_image
	if fn == "proc_image" {
		for scanner.Scan() {
			// 获取一行的文本内容
			line := strings.ReplaceAll(scanner.Text(), "|", "")
			fields := strings.Fields(line)

			if fields[0] == "RESOURCE" || fields[0] == "SCHEDULE" || fields[0] == "SYSCALL" || fields[0] == "USERLOCK" || fields[0] == "KEYTIME" {
				switch fields[0] {
				case "RESOURCE":
					data_type = 1
				case "SCHEDULE":
					data_type = 2
				case "SYSCALL":
					data_type = 3
				case "USERLOCK":
					data_type = 4
				case "KEYTIME":
					data_type = 5
				}
				set_map = 1
				enable_tgid = 0
			} else if set_map == 1 {
				// 对于表头行判断是否已经记录过表头，若没记录过则记录到相应的map中
				if data_map[data_type] == 0 {
					if fields[1] == "PID" {
						for _, value := range fields[2:] {
							switch data_type {
							case 1:
								rsc_titles = append(rsc_titles, value)
							case 2:
								sched_titles = append(sched_titles, value)
							case 3:
								syscall_titles = append(syscall_titles, value)
							case 4:
								ulock_titles = append(ulock_titles, value)
							case 5:
								kt_titles = append(kt_titles, value)
							}
						}
					} else {
						for _, value := range fields[3:] {
							switch data_type {
							case 1:
								rsc_titles = append(rsc_titles, value)
							case 2:
								sched_titles = append(sched_titles, value)
							case 3:
								syscall_titles = append(syscall_titles, value)
							case 4:
								ulock_titles = append(ulock_titles, value)
							case 5:
								kt_titles = append(kt_titles, value)
							}
						}
						enable_tgid = 1
					}
					data_map[data_type] = 1
				}
				set_map = 0
			} else {
				if enable_tgid == 0 {
					// pid 为 fields[1]
					pid, err = strconv.Atoi(fields[1])
					if err != nil {
						// 处理转换错误
						fmt.Println("Error:", err)
						return
					}
				} else if enable_tgid == 1 {
					// pid 为 fields[2]
					pid, err = strconv.Atoi(fields[2])
					if err != nil {
						// 处理转换错误
						fmt.Println("Error:", err)
						return
					}
				}

				switch data_type {
				case 1:
					if _, ok := rsc_pidheader[pid]; !ok {
						if enable_tgid == 0 {
							for _, title := range rsc_titles {
								if enable_tgid == 0 {
									rsc_pidheader[pid] = append(rsc_pidheader[pid], fmt.Sprintf("%s(r)(%s)", fields[1], title))
								} else if enable_tgid == 1 {
									rsc_pidheader[pid] = append(rsc_pidheader[pid], fmt.Sprintf("%s_%s(r)(%s)", fields[1], fields[2], title))
								}
							}
						}
					}
					rsc_Map := make(map[string]interface{})
					mu.Lock()
					rsc_header := rsc_pidheader[pid]
					if enable_tgid == 0 {
						for i, value := range fields[2:] {
							rsc_Map[rsc_header[i]] = value
						}
					} else if enable_tgid == 1 {
						for i, value := range fields[3:] {
							rsc_Map[rsc_header[i]] = value
						}
					}
					mu.Unlock()
					mapchan <- []map[string]interface{}{rsc_Map}
				case 2:
					if _, ok := sched_pidheader[pid]; !ok {
						for _, title := range sched_titles {
							if enable_tgid == 0 {
								sched_pidheader[pid] = append(sched_pidheader[pid], fmt.Sprintf("%s(S)(%s)", fields[1], title))
							} else if enable_tgid == 1 {
								sched_pidheader[pid] = append(sched_pidheader[pid], fmt.Sprintf("%s_%s(S)(%s)", fields[1], fields[2], title))
							}
						}
					}
					sched_Map := make(map[string]interface{})
					mu.Lock()
					sched_header := sched_pidheader[pid]
					if enable_tgid == 0 {
						for i, value := range fields[2:] {
							sched_Map[sched_header[i]] = value
						}
					} else if enable_tgid == 1 {
						for i, value := range fields[3:] {
							sched_Map[sched_header[i]] = value
						}
					}
					mu.Unlock()
					mapchan <- []map[string]interface{}{sched_Map}
				case 3:
					if _, ok := syscall_pidheader[pid]; !ok {
						for _, title := range syscall_titles {
							if enable_tgid == 0 {
								syscall_pidheader[pid] = append(syscall_pidheader[pid], fmt.Sprintf("%s(s)(%s)", fields[1], title))
							} else if enable_tgid == 1 {
								syscall_pidheader[pid] = append(syscall_pidheader[pid], fmt.Sprintf("%s_%s(s)(%s)", fields[1], fields[2], title))
							}
						}
					}
					syscall_Map := make(map[string]interface{})
					mu.Lock()
					syscall_header := syscall_pidheader[pid]
					if enable_tgid == 0 {
						for i, value := range fields[2:] {
							syscall_Map[syscall_header[i]] = value
						}
					} else if enable_tgid == 1 {
						for i, value := range fields[3:] {
							syscall_Map[syscall_header[i]] = value
						}
					}
					mu.Unlock()
					mapchan <- []map[string]interface{}{syscall_Map}
				case 4:
					if _, ok := ulock_pidheader[pid]; !ok {
						for _, title := range ulock_titles {
							if enable_tgid == 0 {
								ulock_pidheader[pid] = append(ulock_pidheader[pid], fmt.Sprintf("%s(l)(%s)", fields[1], title))
							} else if enable_tgid == 1 {
								ulock_pidheader[pid] = append(ulock_pidheader[pid], fmt.Sprintf("%s_%s(l)(%s)", fields[1], fields[2], title))
							}
						}
					}
					ulock_Map := make(map[string]interface{})
					mu.Lock()
					ulock_header := ulock_pidheader[pid]
					if enable_tgid == 0 {
						for i, value := range fields[2:] {
							ulock_Map[ulock_header[i]] = value
						}
					} else if enable_tgid == 1 {
						for i, value := range fields[3:] {
							ulock_Map[ulock_header[i]] = value
						}
					}
					mu.Unlock()
					mapchan <- []map[string]interface{}{ulock_Map}
				case 5:
					if _, ok := kt_pidheader[pid]; !ok {
						for _, title := range kt_titles {
							if enable_tgid == 0 {
								kt_pidheader[pid] = append(kt_pidheader[pid], fmt.Sprintf("%s(k)(%s)", fields[1], title))
							} else if enable_tgid == 1 {
								kt_pidheader[pid] = append(kt_pidheader[pid], fmt.Sprintf("%s_%s(k)(%s)", fields[1], fields[2], title))
							}
						}
					}
					kt_Map := make(map[string]interface{})
					mu.Lock()
					kt_header := kt_pidheader[pid]
					if enable_tgid == 0 {
						for i, value := range fields[2:] {
							kt_Map[kt_header[i]] = value
						}
					} else if enable_tgid == 1 {
						for i, value := range fields[3:] {
							kt_Map[kt_header[i]] = value
						}
					}
					mu.Unlock()
					mapchan <- []map[string]interface{}{kt_Map}
				}
			}
			// 行号递增
			line_number += 1
		}
	} else {
		// 常规方法提取方法
		// 逐行扫描 stdout
		for scanner.Scan() {
			// 获取一行的文本内容
			line := scanner.Text()
			// 处理第一行，提取标题信息
			if line_number == firstline {
				// log.Printf("Title:%s\n", line)
				// 将字符串 line 按照空白字符进行分割，并返回一个切片 parms，其中包含了被空白字符分割的各个子字符串
				parms := strings.Fields(line)
				// 遍历切片 parms 中的每个元素，并将元素的值赋给变量 value。在这里，使用了下划线 _ 表示我们对元素的索引不感兴趣，只关注元素的值
				for _, value := range parms {
					// 根据标题字段的值是否为 "COMM" 确定命令索引，如果不等于，则将 commandindex 的值增加 1
					if strings.ToUpper(value) != "COMM" {
						commandindex = commandindex + 1
					}

					// 创建一个新的空 map，其键是字符串类型，值是空接口类型 interface{}。这种设置允许 map 中的值可以是任何类型
					one_map := make(map[string]interface{})
					// 向 one_map 中添加一个键值对，其中键是字符串 value，值是 nil
					one_map[value] = nil
					// 将新创建的 one_map 添加到切片 maps 中。这样，maps 就成为一个包含了多个这样的 map 的切片
					maps = append(maps, one_map)

					// 将标题字段添加到 titles 切片中
					titles = append(titles, value)
				}
			} else {
				// 使用 strings.Fields 函数将字符串 line 按照空白字符分割成多个字段，返回一个切片 parms。这个切片包含了一行文本中的各个字段
				parms := strings.Fields(line)
				// 声明了一个新的字符串切片 special_parms，用于存储处理后的字段。这个切片将用于存储由原始字段组成的新的字段切片，以保证字段数量与标题数量一致
				var special_parms []string

				// 检查字段数量是否与标题数量一致
				if len(parms) != len(titles) {
					// log.Printf("title number: %d, content number:%d", len(titles), len(parms))
					// 声明一个字符串变量 COMM，用于存储合并后的字段值
					var COMM string
					// 遍历一行文本中的字段(这个遍历过程没看太懂)
					for i, value := range parms {
						// 检查字段是否在命令字段之前或者之后
						if i < commandindex-1 && i >= len(parms)-commandindex {
							// 将特殊处理的字段值添加到 special_parms 切片中
							special_parms = append(special_parms, value)
							// 如果当前字段是命令字段
						} else if i == commandindex-1 {
							// 将当前字段的值赋给 COMM
							COMM = value
							// 如果当前字段在命令字段之前
						} else if i < len(parms)-commandindex {
							// 将当前字段的值追加到 COMM，用空格分隔
							COMM = COMM + " " + value
							// 将合并后的字段值添加到 special_parms 切片中
							special_parms = append(special_parms, COMM)
						}
					}

					// 创建新的 map，并将数据发送到通道
					newMap := make(map[string]interface{})
					mu.Lock()
					// 遍历特殊处理后的字段值
					for i, value := range special_parms {
						// 将字段值与标题对应，构建新的 map
						newMap[titles[i]] = value
					}
					mu.Unlock()
					// 将新创建的 map 发送到通道 mapchan
					mapchan <- []map[string]interface{}{newMap}
					// 如果字段数量与标题数量一致
				} else {
					// 创建新的 map，并将数据发送到通道
					newMap := make(map[string]interface{})
					mu.Lock()
					for i, value := range parms {
						newMap[titles[i]] = value
					}
					mu.Unlock()
					// 将新创建的 map 发送到通道 mapchan
					mapchan <- []map[string]interface{}{newMap}
				}
			}

			// 行号递增
			line_number += 1
		}
	}
}
