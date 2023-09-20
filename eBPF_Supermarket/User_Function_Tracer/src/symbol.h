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
// author: jinyufeng2000@gmail.com
//
// 保存符号信息

#ifndef UTRACE_SYMBOL_H
#define UTRACE_SYMBOL_H

#include <stddef.h>

#include "elf.h"

/**
 * @brief 表示一个符号条目
 */
struct symbol {
  size_t addr; /**< 虚拟地址 */
  size_t size; /**< 符号大小 */
  char* name;  /**< 符号名称（指向堆内存） */
};

/**
 * @brief 符号数组
 * @details 动态扩展的vector
 */
struct symbol_arr {
  int size;           /**< 符号个数 */
  int cap;            /**< 已分配个数 */
  struct symbol* sym; /**< 符号条目数组 */

  struct symbol_arr* next; /**< 下一个符号数组 */
  char* libname;           /**< 该符号数组对应的库/进程名（指向堆内存）*/
};

/**
 * @brief 新建并初始化一个库/进程对应的符号数组
 * @param[in] libname 库/进程名
 * @param[in] dyn_symset 观测进程的动态符号数组
 * @return 指向初始化后的符号数组
 * @details 解析libname对应的ELF格式中的.symtab节和.dynsym节
 *          如果是进程（lib = 0），将.dynsym节的符号加入到dyn_symset集合中
 *          是动态库（lib = 1），只解析在dyn_symset集合中的符号
 */
struct symbol_arr* new_symbol_arr(char* libname);

/**
 * @brief 向符号数组中添加一个符号
 * @param[in] symbols 指向符号数组的指针
 * @param[in] symbol 指向待加入符号的指针
 */
static void push_symbol(struct symbol_arr* symbols, struct symbol* symbol);

/**
 * @brief 从一个符号数组中查找一个虚拟地址对应的符号名称
 * @param[in] symbols 指向符号数组的指针
 * @param[in] addr 待查找的虚拟地址
 * @return addr对应的符号名称
 */
char* find_symbol_name(struct symbol_arr* symbols, size_t addr);

/**
 * @brief 符号表
 * @details 由符号数组组成的链表
 */
struct symbol_tab {
  struct symbol_arr* head; /**< 指向链表头节点的指针 */
};

/**
 * @brief 新建一个符号表
 * @details 在堆上申请空间
 */
struct symbol_tab* new_symbol_tab();

/**
 * @brief 向符号表中添加一个符号数组
 * @param[in] symbol_tab 指向符号表的指针
 * @param[in] symbols 指向要插入的符号数组的指针
 */
void push_symbol_arr(struct symbol_tab* symbol_tab, struct symbol_arr* symbols);

/**
 * @brief 删除一个符号表
 * @param[in] 指向要删除的符号表的指针
 */
void delete_symbol_tab(struct symbol_tab* symbol_tab);

#endif  // UTRACE_SYMTAB_H