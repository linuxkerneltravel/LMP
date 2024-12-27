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
// lock_image数据可视化处理的核心逻辑

package prom_core

import (
	"visualization/dao"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// 定义单条记录的数据结构
type TmuxMetrics struct {
	Max_records   int
	NowTime       float64
	mu            sync.Mutex
	OriginalValue map[string]interface{}
	flag          int
	Records       []Tmux_OneRecord
	Sqlinted      bool
	Sqlobj        *dao.Sqlobj
}

// 原始数据处理后所保留的基本数据
type Tmux_OneRecord struct {
	TimeStamp       float64 `json:"time_stamp"`
	RequestState    string  `json:"request_state"`
	HoldState       string  `json:"hold_state"`
	RequestDuration float64 `json:"request_duration"`
	HoldDuration    float64 `json:"hold_duration"`
}

// Getorigindata 实现通信，获取原始数据
func (t *TmuxMetrics) Getorigindata(originalvalue chan map[string]interface{}) {
	t.OriginalValue = <-originalvalue
}

// 数据库操作
func (t *TmuxMetrics) UpdateSql() {
	t.Sqlobj.Data = t.OriginalValue
	t.Sqlobj.CreateRow()
}

func (t *TmuxMetrics) Initsql() {
	t.Sqlobj.Data = t.OriginalValue
	t.Sqlobj.Connectsql()
	t.Sqlobj.OperateTable("tmux_data", "")
	t.Sqlinted = true
}

// // processJson 实现将原始数据进行处理，获取展示所需要的基本数据
func (t *TmuxMetrics) processJson() Tmux_OneRecord {
	t.flag = 0
	timestamp := float64(0)
	reqstate := ""
	holdstate := ""
	reqduration := float64(0)
	holdduration := float64(0)
	for key, value := range t.OriginalValue {
		if key == "unlock_time(ns)" {
			if value.(string) != "0" {
				t.flag += 1
			}
		} else if key == "acq_time(us)" {
			if value.(string) != "0.000" {
				t.flag += 1
			}
			reqduration, _ = strconv.ParseFloat(value.(string), 64)
			t.NowTime = t.NowTime + reqduration/float64(time.Microsecond)
			timestamp = t.NowTime
		} else if key == "hold_time(us)" {
			if value.(string) != "0.000" {
				t.flag += 1
			}
			holdduration, _ = strconv.ParseFloat(value.(string), 64)
			t.NowTime = t.NowTime + holdduration/float64(time.Microsecond)
			timestamp = t.NowTime
		} else {
			continue
		}
	}
	if t.flag == 0 {
		reqstate = "on_request"
		holdstate = "off_hold"
	} else if t.flag == 1 {
		holdstate = "on_hold"
		reqstate = "off_request"
	} else if t.flag == 3 {
		reqstate = "off_request"
		holdstate = "off_hold"
	}
	record := Tmux_OneRecord{
		TimeStamp:       timestamp,
		RequestState:    reqstate,
		HoldState:       holdstate,
		RequestDuration: reqduration,
		HoldDuration:    holdduration,
	}
	return record
}

// UpdateRecords 对数据进行更新
func (t *TmuxMetrics) UpdateRecords() {
	log.Println(t.OriginalValue)
	if len(t.Records) < t.Max_records {
		t.Records = append(t.Records, t.processJson())
	} else {
		t.Records = append(t.Records, t.processJson())
		t.Records = t.Records[1:]
	}
}

// GetRecordsJSON 将json数据解析为byte数据用于渲染到http中
func (t *TmuxMetrics) GetRecordsJSON() ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return json.Marshal(t.Records)
}

// BootProcService 启动http服务，为grafana暴露http接口，以供数据调用。
func (t *TmuxMetrics) BootProcService() {
	go http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		recordsJson, err := t.GetRecordsJSON()
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
