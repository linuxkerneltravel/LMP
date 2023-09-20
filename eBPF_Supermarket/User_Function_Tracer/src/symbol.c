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

#include "symbol.h"

#include <elf.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "demangle.h"
#include "elf.h"
#include "log.h"

static int addrsort(const void* lhs, const void* rhs) {
  const size_t addrl = ((const struct symbol*)(lhs))->addr;
  const size_t addrr = ((const struct symbol*)(rhs))->addr;

  if (addrl > addrr) return 1;
  if (addrl < addrr) return -1;
  return 0;
}

struct symbol_arr* new_symbol_arr(char* libname) {
  struct elf_head elf;
  if (elf_head_begin(&elf, libname)) return NULL;

  struct symbol_arr* symbols = (struct symbol_arr*)malloc(sizeof(struct symbol_arr));
  symbols->size = 0;
  symbols->cap = 16;  // NOTE
  symbols->sym = (struct symbol*)malloc(symbols->cap * sizeof(struct symbol));
  symbols->next = NULL;
  symbols->libname = strdup(basename(libname));

  struct elf_section elf_s;
  size_t plt_section_off = 0;
  for (elf_section_begin(&elf_s, &elf); elf_section_next(&elf_s, &elf);) {
    if (elf_s.shdr.sh_type != SHT_PROGBITS) continue;

    char* shstr = elf_strptr(elf.e, elf_s.str_idx, elf_s.shdr.sh_name);
    if (strcmp(shstr, ".plt.sec") == 0) {
      plt_section_off = elf_s.shdr.sh_offset;
      break;
    }
  }

  struct symbol sym;
  size_t dyn_str_idx;
  Elf_Data* dyn_sym_data = NULL;
  for (elf_section_begin(&elf_s, &elf); elf_section_next(&elf_s, &elf);) {
    if (elf_s.shdr.sh_type != SHT_DYNSYM && elf_s.shdr.sh_type != SHT_RELA &&
        elf_s.shdr.sh_type != SHT_SYMTAB)
      continue;

    char* shstr = elf_strptr(elf.e, elf_s.str_idx, elf_s.shdr.sh_name);
    if (strcmp(shstr, ".dynsym") != 0 && strcmp(shstr, ".rela.plt") != 0 &&
        strcmp(shstr, ".symtab") != 0)
      continue;

    if (elf_s.shdr.sh_type == SHT_DYNSYM || elf_s.shdr.sh_type == SHT_SYMTAB) {
      struct elf_sym_entry elf_e;
      for (elf_sym_entry_begin(&elf_e, &elf_s); elf_sym_entry_next(&elf_e, &elf_s);) {
        if (elf_s.shdr.sh_type == SHT_DYNSYM) {
          if (dyn_sym_data == NULL) {
            dyn_str_idx = elf_e.str_idx;
            dyn_sym_data = elf_e.sym_data;
          }
          continue;
        }

        if (GELF_ST_TYPE(elf_e.sym.st_info) != STT_FUNC &&
            GELF_ST_TYPE(elf_e.sym.st_info) != STT_GNU_IFUNC)
          continue;
        if (elf_e.sym.st_shndx == STN_UNDEF) continue;
        if (elf_e.sym.st_size == 0) continue;

        sym.addr = elf_e.sym.st_value;
        sym.size = elf_e.sym.st_size;
        sym.name = elf_strptr(elf.e, elf_e.str_idx, elf_e.sym.st_name);
        sym.name = demangle(sym.name);

        push_symbol(symbols, &sym);
      }
    }

    if (elf_s.shdr.sh_type == SHT_RELA) {
      struct elf_rela_entry elf_e;

      int valid = 1;  // TODO
      for (elf_rela_entry_begin(&elf_e, &elf_s, dyn_sym_data);
           elf_rela_entry_next(&elf_e, &elf_s);) {
        if (strlen(elf_strptr(elf.e, dyn_str_idx, elf_e.sym.st_name)) == 0) {
          valid = 0;
          break;
        }
      }

      if (valid) {
        int plt_entry_cnt = 0;
        for (elf_rela_entry_begin(&elf_e, &elf_s, dyn_sym_data);
             elf_rela_entry_next(&elf_e, &elf_s);) {
          sym.addr = plt_section_off + plt_entry_cnt * 0x10;
          ++plt_entry_cnt;
          sym.size = elf_e.sym.st_size;
          if (sym.size > 0) {
            continue;
          }
          sym.name = elf_strptr(elf.e, dyn_str_idx, elf_e.sym.st_name);
          sym.name = demangle(sym.name);
          push_symbol(symbols, &sym);
        }
      }
    }
  }
  elf_head_end(&elf);

  qsort(symbols->sym, symbols->size, sizeof(struct symbol), addrsort);

  DEBUG("Symbols in %s:\n", libname);
  int i = 0;
  for (struct symbol* sym = symbols->sym; sym != symbols->sym + symbols->size; sym++, i++) {
    DEBUG("[%d] %lx %lx %s\n", i + 1, sym->addr, sym->size, sym->name);
  }

  return symbols;
}

static void push_symbol(struct symbol_arr* symbols, struct symbol* symbol) {
  if (symbols->size == symbols->cap) {
    symbols->cap <<= 1;
    symbols->sym = (struct symbol*)realloc(symbols->sym, symbols->cap * sizeof(struct symbol));
  }
  symbols->sym[symbols->size] = *symbol;
  symbols->size++;
}

struct symbol_tab* new_symbol_tab() {
  struct symbol_tab* symtab = (struct symbol_tab*)malloc(sizeof(struct symbol_tab));
  symtab->head = NULL;
  return symtab;
}

void push_symbol_arr(struct symbol_tab* symbol_tab, struct symbol_arr* symbols) {
  symbols->next = symbol_tab->head;
  symbol_tab->head = symbols;
}

void delete_symbol_tab(struct symbol_tab* symbol_tab) {
  for (struct symbol_arr* symbols = symbol_tab->head; symbols != NULL;) {
    for (struct symbol* sym = symbols->sym; sym != symbols->sym + symbols->size; sym++) {
      free(sym->name);
    }
    free(symbols->sym);
    free(symbols->libname);
    struct symbol_arr* next_symbols = symbols->next;
    free(symbols);
    symbols = next_symbols;
  }
  free(symbol_tab);
}

char* find_symbol_name(struct symbol_arr* symbols, size_t addr) {
  for (struct symbol* sym = symbols->sym; sym != symbols->sym + symbols->size; sym++) {
    if (sym->addr <= addr && addr < sym->addr + sym->size) {
      return sym->name;
    } else if (sym->addr == addr && sym->size == 0) {
      return sym->name;
    }
  }
  return NULL;
}