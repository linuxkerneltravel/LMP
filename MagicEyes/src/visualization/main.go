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
// 主函数

// 声明这个文件属于 main 包，是一个可执行的程序
package main

// 导入所需的包，包括自定义的 checker 和 collector 包，以及一些标准库和第三方库
import (
	"visualization/checker"
	"visualization/collector"
	"fmt"
	"log"
	"os"
	"sort"

	"github.com/urfave/cli/v2"
)

// 主函数的开始
func main() {
	// 创建一个新的 CLI 应用
	// cli是一个简单、快速、有趣的包，用于在Go中构建命令行应用程序。其目标是使开发人员能够以一种富有表现力的方式编写快速且可分发的命令行应用程序
	app := cli.NewApp()
	// 配置应用的名称和使用说明文本
	app.Name = "data-visual"
	app.Usage = `	use this cli-tool to collect output data and Convert output data to standard prometheus data.
	here are two different sub-command : collect & ecli
	example:
		sudo data-visual collect ./vfsstat.py
		sudo data-visual proc_image
`
	// 运行 collector 包中的 RunServices 函数，该函数接受一个匿名函数作为回调
	// 该匿名函数将每个服务的实例转换为 cli.Command 接口，并将其添加到应用的命令列表中
	err := collector.RunServices(func(nm string, svc *collector.Aservice) error {
		// 通过服务注册的 NewInst 函数创建服务实例
		ins, err := svc.NewInst(nil)
		if err != nil {
			return err
		}
		// 将 ins 转换为 cli.Command 接口
		cmd, ok := ins.(cli.Command)
		if !ok {
			fmt.Printf("service %s doesn't implement cli.Command\n", nm)
			return fmt.Errorf("service %s doesn't implement cli.Command\n", nm)
		}
		// 将成功转换的命令实例 cmd 添加到应用的命令列表中
		app.Commands = append(app.Commands, &cmd)
		return nil
	})
	// 对应用的命令列表按照名称排序
	sort.Sort(cli.CommandsByName(app.Commands))

	// 设置应用的 Before 钩子，该钩子将在执行命令之前运行
	// Before 钩子函数用于在执行应用程序的命令之前执行一些特定的任务
	app.Before = doBeforeJob
	// 运行 CLI 应用，处理命令行参数，并在执行期间处理错误
	err = app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

// doBeforeJob 函数是应用的 Before 钩子函数，用于在执行命令之前执行一些操作，这里检查并处理错误
func doBeforeJob(ctx *cli.Context) (err error) {
	// 调用 checker 包中的 CheckNormalError 函数检查错误
	checker.CheckNormalError(err)
	return nil
}
