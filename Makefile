# TORX — LD_PRELOAD Tor SOCKS4a shim (research artifact)
# Copyright (c) 2026 <your name>
# SPDX-License-Identifier: MIT
#
# Targets:
#   make            build the shared library
#   make check      build + run static analysis / sanity checks
#   make test       build + run the leak test suite
#   make asan       build with AddressSanitizer + UBSan
#   make debug      build with -O0 -g and debug logging
#   make clean      remove build artifacts
#   make dist       produce a versioned tarball + checksums
#   make install    install to $(PREFIX)/lib (default /usr/local)
#   make uninstall

# ------- Toolchain -------
CC      ?= cc
# NOTE: do not use make's $(LD) — it is predefined as `ld`, which does not
# understand -Wl,... driver flags. Link through $(CC) like everything else.
PREFIX  ?= /usr/local
DESTDIR ?=

# ------- Versioning -------
VERSION := 0.1.0
GIT_REV := $(shell git rev-parse --short HEAD 2>/dev/null || echo "nogit")
TARBALL := torx-$(VERSION)-$(GIT_REV).tar.gz

# ------- Source files (single source of truth) -------
SRC     := torx.c
HDR     := torx.h
OBJ     := $(SRC:.c=.o)
LIB     := libtorx.so

# ------- Flags -------
# -fPIC                 : required for shared object
# -D_GNU_SOURCE         : getrandom, RTLD_NEXT, etc.
# -Wall -Wextra         : baseline warnings
# -Werror               : treat warnings as errors (CI discipline)
# -Wformat=2 ...        : extra format/string checks
# -Wcast-function-type  : catch bad function-pointer casts (dlsym)
# -fstack-protector-strong : canary on buffers
COMMON_WARN := -Wall -Wextra -Werror -Wformat=2 -Wshadow \
               -Wpointer-arith -Wcast-qual -Wcast-function-type \
               -Wstrict-prototypes -Wmissing-prototypes \
               -Wno-unused-parameter

CFLAGS  ?= -O2 -g -fPIC -D_GNU_SOURCE -fstack-protector-strong $(COMMON_WARN)
LDFLAGS ?=
LDLIBS  := -ldl -lpthread

INSTALL_LIB_DIR := $(DESTDIR)$(PREFIX)/lib
INSTALL_BIN_DIR := $(DESTDIR)$(PREFIX)/bin

# ------- Phony -------
.PHONY: all check test asan debug clean dist install install-lib \
        install-bin uninstall help

all: $(LIB)

# ------- Build -------
$(OBJ): $(SRC) $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(LIB): $(OBJ)
	$(CC) $(LDFLAGS) -shared -Wl,-soname,$(LIB) -o $@ $^ $(LDLIBS)

# ------- Sanity checks -------
check: $(LIB)
	@echo ">> verifying exported symbols"
	@nm -D --defined-only $(LIB) | grep -q ' T connect' \
		|| (echo "ERROR: connect not exported"; exit 1)
	@echo ">> verifying no text relocations"
	@! readelf -d $(LIB) | grep -q TEXTREL \
		|| (echo "ERROR: TEXTREL present (bad for security)"; exit 1)
	@echo ">> verifying stack protector"
	@readelf -s $(LIB) | grep -q '__stack_chk_fail' \
		|| echo "WARN: no stack protector symbol; consider -fstack-protector-strong"
	@echo ">> checking for unresolved symbols"
	@! ldd -r $(LIB) 2>&1 | grep -q 'undefined symbol' \
		|| (echo "ERROR: undefined symbols"; ldd -r $(LIB); exit 1)
	@echo ">> taxonomy assertion: DNS hook export state"
	@if nm -D --defined-only $(LIB) | grep -q ' T getaddrinfo'; then \
		echo "NOTE: getaddrinfo is now exported — the documented DNS leak"; \
		echo "      may be fixed. Update LIMITATIONS.md §1 and the dns.*"; \
		echo "      cases in tests/leak/run.sh before trusting this."; \
	else \
		echo "confirmed: getaddrinfo not exported -> DNS leak stands"; \
		echo "      (LIMITATIONS.md §1, tests/leak id dns.export.getaddrinfo)"; \
	fi
	@echo "check: OK"

# ------- Tests -------
# Full leak harness: static rows always run; dynamic rows degrade to
# UNTESTED when there is no egress (see tests/leak/README.md).
test: $(LIB)
	./tests/leak/run.sh

# ------- Variants -------
# ASan/UBSan build. Note: ASan itself LD_PRELOADs, so don't stack
# it with the shim when wrapping real apps — use for unit tests only.
asan: CFLAGS := -O1 -g -fPIC -D_GNU_SOURCE -fstack-protector-strong \
                $(COMMON_WARN) -fsanitize=address,undefined \
                -fno-omit-frame-pointer
asan: LDFLAGS := -fsanitize=address,undefined
asan: clean $(LIB)

debug: CFLAGS := -O0 -g3 -fPIC -D_GNU_SOURCE -fstack-protector-strong \
                 $(COMMON_WARN) -DTORX_DEBUG_DEFAULT=1
debug: clean $(LIB)

# ------- Install -------
install: install-lib install-bin

install-lib: $(LIB)
	install -d $(INSTALL_LIB_DIR)
	install -m 0755 $(LIB) $(INSTALL_LIB_DIR)/$(LIB)
	@echo "installed $(INSTALL_LIB_DIR)/$(LIB)"

install-bin: bin/torx
	install -d $(INSTALL_BIN_DIR)
	install -m 0755 bin/torx $(INSTALL_BIN_DIR)/torx
	@echo "installed $(INSTALL_BIN_DIR)/torx"

uninstall:
	rm -f $(INSTALL_LIB_DIR)/$(LIB)
	rm -f $(INSTALL_BIN_DIR)/torx

# ------- Distribution -------
dist: check
	@echo ">> building $(TARBALL)"
	@rm -rf dist && mkdir -p dist/torx-$(VERSION)
	@for f in $(SRC) $(HDR) Makefile README.md THREAT_MODEL.md LIMITATIONS.md DETECTION.md SECURITY.md; do \
		[ -f "$$f" ] && cp -v "$$f" dist/torx-$(VERSION)/ || true; \
	done
	@[ -d bin ] && cp -rv bin dist/torx-$(VERSION)/ || true
	@[ -d docs ] && cp -rv docs dist/torx-$(VERSION)/ || true
	@[ -d tests ] && cp -rv tests dist/torx-$(VERSION)/ || true
	@rm -rf dist/torx-$(VERSION)/tests/leak/.build
	@tar -C dist -czf dist/$(TARBALL) torx-$(VERSION)
	@cd dist && sha256sum $(TARBALL) > $(TARBALL).sha256
	@echo ">> artifacts:"
	@ls -lh dist/$(TARBALL) dist/$(TARBALL).sha256

# ------- Clean -------
clean:
	rm -f $(OBJ) $(LIB)
	rm -rf dist

# ------- Help -------
help:
	@echo "targets: all check test asan debug install uninstall dist clean"
	@echo ""
	@echo "variables:"
	@echo "  CC=$(CC)  PREFIX=$(PREFIX)  DESTDIR=$(DESTDIR)"
	@echo "  CFLAGS=$(CFLAGS)"