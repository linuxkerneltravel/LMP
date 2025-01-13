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
// 数据持久化的方式：通过将数据写入数据库实现数据持久化。

package dao

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var GlobalMap map[int][6]bool

// 定义一个名为 Sqlobj 的结构体类型，用于封装数据库相关的信息
type Sqlobj struct {
	// Tablename 字段存储数据库表的名称。
	Tablename string
	// db 字段是一个指向 gorm.DB 类型的指针，用于处理与数据库交互的对象。
	db *gorm.DB
	// Data 字段是一个 map，存储与数据库相关的信息。
	Data map[string]interface{}
}

type Basicdata struct {
	ID int `gorm:"primaryKey;unique;column:ID"`
}

// Connectsql 连接数据库
func (s *Sqlobj) Connectsql() {
	currentdir, _ := os.Getwd()
	path := currentdir + "/dao/data.db"
	db, _ := gorm.Open(sqlite.Open(path), &gorm.Config{})
	log.Println("connected.")
	s.db = db
}

func (s *Sqlobj) Tableexist(name string) bool {
	return s.db.Migrator().HasTable(name)
}

// CreateTable 建表
func (s *Sqlobj) OperateTable(name string, fn string) {
	// 检查表是否存在
	if !s.Tableexist(name) {
		// 如果表不存在，先删除已存在的同名表
		deletetable := fmt.Sprintf("drop table if exists %s;", s.Tablename)
		// 执行SQL语句，删除表
		if err := s.db.Exec(deletetable).Error; err != nil {
			log.Fatalf("drop exist table failed.")
		}
		// 创建表
		if err := s.db.Table(s.Tablename).AutoMigrate(&Basicdata{}); err != nil {
			log.Fatalf("create table failed.")
		}
		// 添加表
		if fn == "proc_image" {
			s.ProcAppendTable()
		} else {
			s.AppendTable()
		}
		// 创建行
		s.CreateRow()
	} else {
		// 如果表存在，直接创建行
		s.CreateRow()
	}
}

// AppendTable 扩展表
func (s *Sqlobj) AppendTable() {
	for key, value := range s.Data {
		datatype := "text"
		if strvalue, is_string := value.(string); is_string {
			// shift numerical data to float64
			if _, err := strconv.ParseFloat(strvalue, 64); err == nil {
				datatype = "real"
			}
		}
		addcolumn := fmt.Sprintf("alter table %s add column \"%s\" %s", s.Tablename, key, datatype)
		s.db.Exec(addcolumn)
	}
}

func (s *Sqlobj) ProcAppendTable() {
	enable := false
	data := 0
	// 遍历数据集合
	for key, value := range s.Data {
		if !enable {
			var pid int
			index := strings.Index(key, "(")
			intPart := key[:index]
			parts := strings.Split(intPart, "_")
			if len(parts) >= 2 {
				pid, _ = strconv.Atoi(parts[1])
			} else {
				pid, _ = strconv.Atoi(intPart)
			}
			leftIndex := strings.Index(key, "(")
			rightIndex := strings.Index(key, ")")
			if leftIndex != -1 && rightIndex != -1 && rightIndex > leftIndex {
				substring := key[leftIndex+1 : rightIndex]
				switch substring {
				case "r":
					data = 1
				case "S":
					data = 2
				case "s":
					data = 3
				case "l":
					data = 4
				case "k":
					data = 5
				}
			}

			if _, ok := GlobalMap[pid]; !ok {
				GlobalMap[pid] = [6]bool{false, false, false, false, false, false}
				array := GlobalMap[pid]
				array[data] = true
				GlobalMap[pid] = array
			} else {
				array := GlobalMap[pid]
				if array[data] {
					break
				}
				array[data] = true
				GlobalMap[pid] = array
			}
			enable = true
		}
		// 默认数据类型为"text"
		datatype := "text"
		// 检查值是否为字符串类型
		if strvalue, is_string := value.(string); is_string {
			// 如果值为字符串类型，则尝试将其转换为浮点数
			if _, err := strconv.ParseFloat(strvalue, 64); err == nil {
				// 如果可以成功转换，则将数据类型设置为"real"
				datatype = "real"
			}
		}
		// 构建SQL语句，用于向表中添加列
		addcolumn := fmt.Sprintf("alter table %s add column \"%s\" %s", s.Tablename, key, datatype)
		// 执行SQL语句，向表中添加列
		s.db.Exec(addcolumn)
	}
}

// CreateRow 写入数据
func (s *Sqlobj) CreateRow() {
	// 使用数据库连接对象创建行，并将数据插入指定表中
	s.db.Table(s.Tablename).Create(s.Data)
}

func init() {
	GlobalMap = make(map[int][6]bool)
}
