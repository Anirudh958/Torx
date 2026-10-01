# netns/ — Phase 2 chunk 6b: the fail-closed boundary launcher
# (docs/enforcement.md §5; run by tests/enforce/run.sh boundary_up).
#
# Flags mirror the root Makefile's warning set; the launcher is a
# security boundary, so -Werror and the hardening flags stay on.

CC      ?= cc
COMMON_WARN := -Wall -Wextra -Werror -Wformat=2 -Wshadow \
               -Wpointer-arith -Wcast-qual -Wstrict-prototypes \
               -Wmissing-prototypes -Wno-unused-parameter
CFLAGS  ?= -O2 -g -D_GNU_SOURCE -fstack-protector-strong $(COMMON_WARN)
LDFLAGS ?=

LAUNCHER := torx-launch
SRC      := torx-launch.c

.PHONY: all clean check

all: $(LAUNCHER)

$(LAUNCHER): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

# usage contract smoke — no state, no unshare, safe anywhere
check: $(LAUNCHER)
	@./$(LAUNCHER) 2>/dev/null; test $$? -eq 64 && echo "usage contract: ok"

clean:
	rm -f $(LAUNCHER)
