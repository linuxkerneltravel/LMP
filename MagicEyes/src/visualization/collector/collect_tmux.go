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
// 为lock_image所做的适配的收集器

package collector

import (
	"bufio"
	"visualization/checker"
	"github.com/urfave/cli/v2"
	"io"
	"strings"
)

type Tmux_Setting struct {
	Name        string `yaml:"tmux_name"`
	Path        string `yaml:"tmux_path"`
	Pid         string `yaml:"tmux_pid"`
	Max_Records int    `yaml:"tmux_max_records"`
}

var tmux_command = cli.Command{
	Name:   "tmux",
	Usage:  "Special collect data out from lock_image",
	Action: tmuxCollect,
}

func tmuxCollect(ctx *cli.Context) error {
	_, command, _ := Get_Setting("tmux")
	return ProcRun(command)
}

func redirectTmux(stdout io.ReadCloser, mapchan chan map[string]interface{}) {
	controler := 0
	scanner := bufio.NewScanner(stdout)
	onemap := make(map[string]interface{})

	for scanner.Scan() {
		line := scanner.Text()
		line = checker.CutunexceptedSpace(line)

		if controler == 0 {
			if checker.Istmuxlineone(line) {
				parms := strings.Fields(line)
				for _, value := range parms {
					parts := strings.Split(value, ":")
					onemap[parts[0]] = parts[1]
					controler = 1
				}
			}
		} else {
			if checker.Istmuxlinetwo(line) {
				parms := strings.Fields(line)
				for _, value := range parms {
					parts := strings.Split(value, ":")
					onemap[parts[0]] = parts[1]
					controler = 0
				}
				mapchan <- onemap
				onemap = make(map[string]interface{})
			}
		}
	}
}
