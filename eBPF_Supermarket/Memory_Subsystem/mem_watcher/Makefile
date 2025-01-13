# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
CLANG ?= clang
LIBBPF_SRC := $(abspath ../../lib/libbpf/src)
BPFTOOL_SRC := $(abspath ../../lib/bpftool/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
LIBBLAZESYM_SRC := $(abspath ../blazesym/)
LIBBLAZESYM_INC := $(abspath ../blazesym/capi/include)
LIBBLAZESYM_OBJ := $(abspath $(OUTPUT)/libblazesym_c.a)
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')
VMLINUX := ../vmlinux/$(ARCH)/vmlinux.h
# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
INCLUDES := -I$(OUTPUT) -I../../libbpf/include/uapi -I$(dir $(VMLINUX)) -I$(LIBBLAZESYM_INC) -I./include
CFLAGS := -g -Wall
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

APPS = paf pr procstat sysstat memleak fraginfo vmasnap drsnoop oomkiller numafraginfo slabrate

TARGETS= mem_watcher
CARGO ?= $(shell which cargo)
ifeq ($(strip $(CARGO)),)
BZS_APPS :=
else
BZS_APPS := 


# Required by libblazesym
ALL_LDFLAGS += -lrt -ldl -lpthread -lm
endif

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

.PHONY: all
all: $(TARGETS)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(TARGETS)

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

# Build bpftool
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap


$(LIBBLAZESYM_SRC)/target/release/libblazesym_c.a::
	$(Q)cd $(LIBBLAZESYM_SRC) && $(CARGO) build --package=blazesym-c --release

$(LIBBLAZESYM_OBJ): $(LIBBLAZESYM_SRC)/target/release/libblazesym_c.a | $(OUTPUT)
	$(call msg,LIB, $@)
	$(Q)cp $(LIBBLAZESYM_SRC)/target/release/libblazesym_c.a $@

# Build BPF code
$(OUTPUT)/%.bpf.o: bpf/%.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX) | $(OUTPUT) $(BPFTOOL)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)		      \
		     $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES)		      \
		     -c $(filter %.c,$^) -o $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
	$(Q)$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)

# Generate BPF skeletons
.PHONY: $(APPS)
$(APPS): %: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $(OUTPUT)/$@.skel.h

# Build user-space code
$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OUTPUT)/$(TARGETS).o: $(TARGETS).c $(APPS) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(patsubst %,$(OUTPUT)/%.o,$(TARGETS)): $(LIBBLAZESYM_OBJ)

$(TARGETS): $(LIBBLAZESYM_OBJ)

# Build application binary
$(TARGETS): %: $(OUTPUT)/%.o $(COMMON_OBJ) $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lstdc++ -lelf -lz -o $@

SUCCESS_MESSAGE:
	@echo "\e[38;2;255;102;204m                                          _       _               \e[0m"
	@echo "\e[38;2;255;153;204m  _ __ ___   ___ _ __ ___  __      ____ _| |_ ___| |__   ___ _ __ \e[0m"
	@echo "\e[38;2;255;204;204m | '_ \` _ \ / _ \ '_ \` _ \ \ \ /\ / / _\` | __/ __| '_ \ / _ \ '__|\e[0m"
	@echo "\e[38;2;204;229;255m | | | | | |  __/ | | | | | \ V  V / (_| | || (__| | | |  __/ |   \e[0m"
	@echo "\e[38;2;153;204;255m |_| |_| |_|\___|_| |_| |_|  \_/\_/ \__ _|\__\___|_| |_|\___|_|   \e[0m"

	@echo "\e[38;2;0;255;255mSuccessful to compile mem_watcher tools:                      \e[0m"
	@echo "\e[38;2;0;255;255mPlease start your use ~                                      \e[0m"
all: $(TARGETS) SUCCESS_MESSAGE

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
