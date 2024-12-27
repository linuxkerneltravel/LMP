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
// proc_image数据可视化处理的核心逻辑

package prom_core

import (
	"visualization/dao"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"
)

// 定义单条记录的数据结构
type ProcMetrics struct {
	Max_records   int
	NowTime       float64
	mu            sync.Mutex
	OriginalValue map[string]interface{}
	Records       []OneRecord
	Sqlinted      bool
	Sqlobj        *dao.Sqlobj
}

// 原始数据处理后所保留的基本数据
type OneRecord struct {
	TimeStamp float64 `json:"timestamp"`
	State     string  `json:"state"`
	Durtion   float64 `json:"durtion"`
}

// Getorigindata 实现通信，获取原始数据
func (p *ProcMetrics) Getorigindata(originalvalue chan map[string]interface{}) {
	p.OriginalValue = <-originalvalue
}

// 数据库操作
func (p *ProcMetrics) UpdateSql() {
	p.Sqlobj.Data = p.OriginalValue
	p.Sqlobj.CreateRow()
}

func (p *ProcMetrics) Initsql() {
	p.Sqlobj.Data = p.OriginalValue
	p.Sqlobj.Connectsql()
	p.Sqlobj.OperateTable("proc_image", "")
	p.Sqlinted = true
}

// processJson 实现将原始数据进行处理，获取展示所需要的基本数据
func (p *ProcMetrics) processJson() OneRecord {
	timestamp := float64(0)
	state := ""
	durtion := float64(0)
	for key, value := range p.OriginalValue {
		if key == "flag" {
			if value.(string) == "1" {
				state = "offcpu"
			} else {
				state = "oncpu"
			}
		} else if key == "time" {
			durtion, _ = strconv.ParseFloat(value.(string), 64)
			p.NowTime = p.NowTime + durtion
			timestamp = p.NowTime
		} else {
			continue
		}
	}

	onerecord := OneRecord{TimeStamp: timestamp, State: state, Durtion: durtion}
	return onerecord
}

// UpdateRecords 对数据进行更新
func (p *ProcMetrics) UpdateRecords() {
	log.Println(p.OriginalValue)
	if len(p.Records) < p.Max_records {
		p.Records = append(p.Records, p.processJson())
	} else {
		p.Records = append(p.Records, p.processJson())
		p.Records = p.Records[1:]
	}
}

// GetRecordsJSON 将json数据解析为byte数据用于渲染到http中
func (p *ProcMetrics) GetRecordsJSON() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return json.Marshal(p.Records)
}

// BootProcService 启动http服务，为grafana暴露http接口，以供数据调用。
func (p *ProcMetrics) BootProcService() {
	go http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		recordsJson, err := p.GetRecordsJSON()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(recordsJson)
	})
	go func() {
		if err := http.ListenAndServe(":8090", nil); err != nil {
			log.Fatalf("Failed to start HTTP server:", err)
		}
	}()
	select {}
}
