# C data plane build
VERSION ?= 1.0.0
CC      ?= gcc
PKG     ?= pkg-config
DPDK_CFLAGS ?= $(shell $(PKG) --cflags libdpdk)
DPDK_LIBS   ?= $(shell $(PKG) --libs libdpdk)

ROOT    := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
BUILD   := $(ROOT)/build/core
OBJ     := $(BUILD)/obj
BIN     := $(BUILD)/dpdk-tunnel-router
LIB     := $(BUILD)/librouter.a
SRC     := $(wildcard src/*.c)
OBJS    := $(patsubst src/%.c,$(OBJ)/%.o,$(SRC))
TEST_SRC:= $(wildcard tests/*.c)
TESTS   := $(patsubst tests/%.c,$(BUILD)/%,$(TEST_SRC))
BENCH   := $(BUILD)/engine_bench
PROF    := $(BUILD)/engine_prof
AB      := $(BUILD)/engine_ab
AB_BASE ?=
AB_REF  := $(BUILD)/engine_ref.o

CFLAGS  ?= -O3 -g
CFLAGS  += -std=gnu11 -Wall -Wextra -Wshadow -Wformat=2 -Wno-unused-parameter \
           -D_GNU_SOURCE -DTR_VERSION=\"$(VERSION)\" -pthread -Isrc $(DPDK_CFLAGS)
LDFLAGS += $(DPDK_LIBS) -pthread -ldl -lm

.PHONY: all clean test tests bench prof prof-run ab ab-run
all: $(BIN)

$(OBJ)/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

$(LIB): $(OBJS)
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $^

$(BIN): $(OBJ)/main.o $(LIB)
	@mkdir -p $(dir $@)
	$(CC) $(OBJ)/main.o $(LIB) $(LDFLAGS) -o $@

$(BUILD)/%: tests/%.c $(LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

tests: $(TESTS)

$(BENCH): bench/engine_bench.c $(LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

bench: $(BENCH)
	@mkdir -p $(ROOT)/run $(ROOT)/tmp
	XDG_RUNTIME_DIR=$(ROOT)/run TMPDIR=$(ROOT)/tmp $(BENCH)

# Development-only statistical profiler (see bench/engine_prof.c).
$(PROF): bench/engine_prof.c $(LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

prof: $(PROF)

prof-run: $(PROF)
	@mkdir -p $(ROOT)/run $(ROOT)/tmp
	XDG_RUNTIME_DIR=$(ROOT)/run TMPDIR=$(ROOT)/tmp $(PROF)

# Interleaved A/B harness: links a reference build of engine.c next to the
# engine under test.  AB_BASELINE must point at the reference engine.c.
ifeq ($(strip $(AB_BASELINE)),)
.PHONY: $(AB_REF)
$(AB_REF):
	@echo "AB_BASELINE=<path to the reference engine.c> is required"; exit 1
else
$(AB_REF): $(AB_BASELINE)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -include bench/engine_v2_rename.h -c $< -o $@
endif

$(AB): bench/engine_ab.c $(LIB) $(AB_REF)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $< $(AB_REF) $(LIB) $(LDFLAGS) -o $@

ab: $(AB)

ab-run: $(AB)
	@mkdir -p $(ROOT)/run $(ROOT)/tmp
	XDG_RUNTIME_DIR=$(ROOT)/run TMPDIR=$(ROOT)/tmp $(AB)

test: $(TESTS)
	@mkdir -p $(ROOT)/run $(ROOT)/tmp
	@chmod 700 $(ROOT)/run
	@set -e; for t in $(TESTS); do \
	    echo "== $$t"; \
	    XDG_RUNTIME_DIR=$(ROOT)/run TMPDIR=$(ROOT)/tmp $$t; \
	done

clean:
	rm -rf $(BUILD)

-include $(OBJS:.o=.d)
