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
// Prometheus可视化的核心逻辑，实现将规范化的数据加载到Prometheus的metrics中，并启动http服务，供Prometheus-Service提取。

package prom_core

import (
	"visualization/checker"
	"visualization/dao"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// 定义一个名为 MyMetrics 的结构体类型。
type MyMetrics struct {
	// BPFName 字段存储与此度量相关的 BPF 的名称。
	BPFName string
	// mu 字段是一个互斥锁，用于在多协程之间同步对结构体字段的访问。
	mu sync.Mutex
	// Maps 字段是一个 map，存储与此度量相关的信息。
	Maps map[string]interface{}
	// Maplist 字段是一个切片，存储与此度量相关的信息的列表。
	Maplist []map[string]interface{}
	// Sqlobj 字段是一个指向 dao.Sqlobj 类型的指针，用于处理与数据库相关的信息。
	Sqlobj *dao.Sqlobj
	// Sqlinited 字段表示与此度量相关的数据库是否已初始化。
	Sqlinited bool
}

func (m *MyMetrics) Describe(ch chan<- *prometheus.Desc) {}

// Convert_Maps_To_Dict shift dict list to dict
func (m *MyMetrics) UpdateData() {
	new_Dict := make(map[string]interface{})
	for _, dict := range m.Maplist {
		for key, value := range dict {
			new_Dict[key] = value
		}
	}
	m.Maps = new_Dict
}

func (m *MyMetrics) UpdataSql(fn string) {
	m.Sqlobj.Data = m.Maps
	if fn == "proc_image" {
		m.Sqlobj.ProcAppendTable()
	}
	m.Sqlobj.CreateRow()
}

func (m *MyMetrics) Initsql(fn string) {
	m.Sqlobj.Data = m.Maps
	m.Sqlobj.Connectsql()
	m.Sqlobj.OperateTable(m.BPFName, fn)
	m.Sqlinited = true
}

// Format_Dict format dict.
func Format_Dict(dict map[string]interface{}) (map[string]float64, map[string]string) {
	measurable_dict := map[string]float64{}
	string_dict := map[string]string{}
	for key, value := range dict {
		if strvalue, is_string := value.(string); is_string {
			// shift numerical data to float64
			if floatValue, err := strconv.ParseFloat(strvalue, 64); err == nil {
				measurable_dict[key] = floatValue
			} else {
				if checker.Isinvalid(key) || strings.ToUpper(key) == "TIME" || strings.ToUpper(key) == "SOCK" {
					continue
				}
				string_dict[key] = value.(string)
			}
		}
	}
	return measurable_dict, string_dict
}

// Collect func collect data and load to metrics.
func (m *MyMetrics) Collect(ch chan<- prometheus.Metric) {
	bpfdata, stringdata := Format_Dict(m.Maps)
	for key, value := range bpfdata {
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				"bpf_metrics",
				"collect data and load to metrics",
				[]string{"bpf_out_data"},
				stringdata,
			),
			prometheus.GaugeValue,
			value,
			key,
		)
	}
}

// StartService 方法是 MyMetrics 类型的一个方法，用于启动服务并将 MyMetrics 注册到 Prometheus。
func (m *MyMetrics) StartService() {
	// 使用 Prometheus 的 MustRegister 函数将 MyMetrics 注册到 Prometheus 收集器中。
	prometheus.MustRegister(m)

	// 将 /metrics 路径映射到 Prometheus HTTP 处理器，以便可以通过该路径访问指标数据。
	http.Handle("/metrics", promhttp.Handler())

	// 启动 HTTP 服务器，监听端口 8090，处理器为 nil（使用默认的多路复用器）。
	// 如果启动失败，使用 log.Fatalf 输出错误信息并终止程序。
	if err := http.ListenAndServe(":8090", nil); err != nil {
		log.Fatalf("Failed to start HTTP server:", err)
	}
}
