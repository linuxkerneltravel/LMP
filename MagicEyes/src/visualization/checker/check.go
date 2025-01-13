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
// 该文件用于对输入进行合法性检查以及对输入进行初步的处理。

package checker

import (
	"fmt"
	"github.com/urfave/cli/v2"
	"log"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	MaxFileSize int64 = 100 * 1024 * 1024
)

// 定义了一个名为 CollectCheck 的函数，用于检查和获取要收集的文件路径及其他参数
func CollectCheck(ctx *cli.Context) (string, error) {
	//if err := CheckArgs(ctx, 1, ConstExactArgs); err != nil {
	//	return "", err
	//}

	// 从命令行上下文中获取第一个参数，即文件路径
	file := ctx.Args().Get(0)

	// 检查输入字符串是否有效
	if !IsInputStringValid(file) {
		return "", fmt.Errorf("input:%s is invalid", file)
	}

	// 检查文件是否存在
	exist, err := PathExist(file)
	if err != nil {
		return "", err
	}
	// 如果文件不存在，返回相应的错误信息
	if !exist {
		return "", fmt.Errorf("file %s is not exist", file)
	}

	// 获取完整的命令行参数，并将它们连接成一个字符串
	// fullcommand 是一个包含参数的字符串切片
	fullcommand := ctx.Args().Slice()
	// 将字符串切片中的元素连接成一个字符串，fullcommand 是一个包含命令行参数的字符串切片，" " 是连接各个参数时使用的分隔符
	full := strings.Join(fullcommand, " ")

	// 返回完整的命令行参数作为结果，以及 nil 表示没有错误
	return full, nil
}

func IsInputStringValid(input string) bool {
	if input != "" {
		if isOk, _ := regexp.MatchString("^[a-zA-Z0-9/._-]*$", input); isOk {
			return isOk
		}
	}
	return false
}

func PathExist(path string) (bool, error) {
	fileInfo, err := os.Stat(path)
	if err == nil {
		if !fileInfo.IsDir() && fileInfo.Size() > MaxFileSize {
			return true, fmt.Errorf("the size of %s exceeds"+
				" the maximum value which is %d", fileInfo.Name(), MaxFileSize)
		}
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// 定义了一个名为 CheckNormalError 的函数，用于检查并处理普通的错误
func CheckNormalError(err error) {
	// 如果 err 不为 nil，表示发生了错误
	if err != nil {
		// 使用 log.Fatalln 打印错误信息并终止程序
		log.Fatalln(err)
	}
}

// 该函数接收一个字符串参数 content，用于判断是否符合 "proc" 命令的输出格式
func IsProcOutput(content string) bool {
	// 定义了一个包含正则表达式的字符串，用于匹配 "proc" 命令的输出格式。该正则表达式包含了多个条件，用 | 分隔
	pattern := `flag:\d+\s+pid:\d+\s+comm:\S+\s+offcpu_id|oncpu_time:\d+\s+offcpu_time|oncpu_time:\d+\s+oncpu_id|offcpu_id:\d+\s+oncpu_time|offcpu_time:\d+\s+time:[\d.]+`
	// 将字符串正则表达式编译成一个正则表达式对象 re
	re := regexp.MustCompile(pattern)
	// 检查传入的 content 是否与正则表达式匹配，如果匹配则返回 true，否则返回 false
	return re.MatchString(content)
}

func CutunexceptedSpace(content string) string {
	re := regexp.MustCompile(`\s*:\s*`)
	result := re.ReplaceAllString(content, ":")
	return result
}

func ConvertTimeStamp(timestamp int64) string {
	t := time.Unix(0, timestamp)
	formattedTime := t.Format("15:04:05.000000")
	return formattedTime
}
func Isinvalid(string2 string) bool {
	pattern := `<.*>`
	re := regexp.MustCompile(pattern)
	return re.MatchString(string2)
}

func IsTCPwatchFirst(string2 string) bool {
	pattern := `^\s*SOCK\s*COMM\s*SEQ\s*ACK\s*MAC_TIME\s*IP_TIME\s*TCP_TIME\s*RX\s*$`
	re := regexp.MustCompile(pattern)
	return re.MatchString(string2)
}

func IsTcpObjection(string2 string) bool {
	pattern := `netwatch`
	match, _ := regexp.MatchString(pattern, string2)
	return match
}

func IsProcimage(string2 string) bool {
	pattern := `proc`
	match, _ := regexp.MatchString(pattern, string2)
	return match
}

func InvalidTcpData(string2 string) bool {
	pattern1 := `invalid`
	pattern2 := `User-Agent`
	match1, _ := regexp.MatchString(pattern1, string2)
	match2, _ := regexp.MatchString(pattern2, string2)
	if match2 || match1 {
		return true
	}
	return false
}

func Istmuxlineone(string2 string) bool {
	is, _ := regexp.MatchString(`pid`, string2)
	return is
}

func Istmuxlinetwo(string2 string) bool {
	is, _ := regexp.MatchString(`acq_time`, string2)
	return is
}
