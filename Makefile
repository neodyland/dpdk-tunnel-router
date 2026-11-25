# dpdk-tunnel-router — top-level build
#
#   make            build C core, Rust tunnel-driver library and routerctl
#   make test       build and run unit tests + live net_null smoke test
#   make clean

SHELL := /bin/bash
ROOT  := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
CARGO := $(ROOT)/scripts/cargo.sh
BUILD := $(ROOT)/build

.PHONY: all core rust rust-lib cli test core-test rust-test smoke vm-test clean install
.PHONY: distclean

all: core rust

core:
	$(MAKE) -C core

rust: rust-lib cli

rust-lib:
	$(CARGO) build --release -p tunnel-driver
	$(CARGO) build --examples -p tunnel-driver

cli:
	$(CARGO) build --release -p routerctl

core-test: core rust-lib
	$(MAKE) -C core test

rust-test:
	$(CARGO) test --workspace

test: core-test rust-test smoke

smoke: all
	./scripts/smoke-test.sh

vm-test: all
	./tests/vm/run-vm-tests.sh

install: all
	install -D -m 0755 $(BUILD)/core/dpdk-tunnel-router $(DESTDIR)/usr/local/sbin/dpdk-tunnel-router
	install -D -m 0755 $(BUILD)/rust/release/routerctl $(DESTDIR)/usr/local/bin/routerctl
	install -D -m 0755 $(BUILD)/rust/release/libtunnel_driver.so $(DESTDIR)/usr/local/lib/dpdk-tunnel-router/libtunnel_driver.so
	install -D -m 0644 config/example.conf $(DESTDIR)/usr/local/share/dpdk-tunnel-router/example.conf

clean:
	$(MAKE) -C core clean
	rm -rf $(BUILD) run tmp vmtest
	mkdir -p run tmp

distclean: clean
	rm -rf rust/target .cargo-home
