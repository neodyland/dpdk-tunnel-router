# C data plane build
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

CFLAGS  ?= -O2 -g
CFLAGS  += -std=gnu11 -Wall -Wextra -Wshadow -Wformat=2 -Wno-unused-parameter \
           -D_GNU_SOURCE -pthread -Isrc $(DPDK_CFLAGS)
LDFLAGS += $(DPDK_LIBS) -pthread -ldl -lm

.PHONY: all clean test
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
