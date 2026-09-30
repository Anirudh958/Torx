# Build notes

Practical notes for anyone touching the build. Everything here corresponds to
something that actually bit us; the gotchas are not theoretical.

## Targets

| target | what it does |
|---|---|
| `make` | `torx.o` → `libtorx.so` (via `$(CC) -shared -Wl,-soname`) |
| `make check` | build + `nm`/`readelf`/`ldd` assertions incl. the DNS taxonomy assertion |
| `make test` | build + `tests/leak/run.sh` (static always; dynamic degrades to UNTESTED without egress) |
| `make asan` / `make debug` | sanitizer / `-O0 -g3 -DTORX_DEBUG_DEFAULT=1` variants (both `clean` first) |
| `make dist` | `check`, then versioned tarball + sha256 under `dist/` |
| `make install` | `libtorx.so` → `$(PREFIX)/lib`, `bin/torx` → `$(PREFIX)/bin` |

Variables: `CC`, `CFLAGS`, `LDFLAGS`, `PREFIX`, `DESTDIR` are all `?=`
overridable. `LD` deliberately is **not** used (below).

## Gotchas

### 1. Never link with `$(LD)`

Make predefines `LD=ld`. `ld` is the *backend* linker: it does not understand
driver flags like `-Wl,-soname,...`, `-shared` as a driver concept, or
`-fsanitize`. The historical `LD ?= $(CC)` line looked harmless but shipped a
footgun (`LD=ld make` silently breaks the link). The link rule calls
`$(CC)` directly; `LD` is not referenced anywhere in the Makefile.

### 2. `_GNU_SOURCE` must precede every libc header

`RTLD_NEXT`, `getrandom(2)` and friends are glibc extensions hidden behind
`_GNU_SOURCE`. If any libc header gets included first, the feature macros are
already expanded and the symbols never appear. Therefore:

- `torx.h` and `torx.c` each carry their own `#ifndef _GNU_SOURCE / #define`
  guard **before their first `#include`** (either file may be the first one
  included, and `torx.h` is public — consumers include it too).
- The Makefile also passes `-D_GNU_SOURCE` for belt-and-braces.

Defining it *without* the `#ifndef` guard in a header breaks any TU that
already defined it differently (`-Wundef`/redefinition warnings under
`-Werror`).

### 3. Header hygiene

- Include guard `TORX_H` (and `#endif /* TORX_H */` — an unguarded end of
  file was caught once already).
- Configuration lives in `TORX_*` macros (`TORX_DEFAULT_PROXY`,
  `TORX_DEFAULT_PORT`, `TORX_USERID`, …), not string literals sprinkled
  through `torx.c`.
- The hook prototype in `torx.h` must match libc **exactly**
  (`int connect(int, const struct sockaddr *, socklen_t)`) — a mismatch
  compiles fine under some flags and then misroutes at runtime.

### 4. `dlsym` and function pointers

`dlsym(3)` returns `void *`. Casting `void *` to a function pointer and
calling it is rejected by `-Wcast-function-type` (and is an ISO C
constraint violation even though POSIX guarantees `dlsym`'s result). The
`RESOLVE_SYM` macro copies the bytes with `memcpy`, which is the
POSIX-sanctioned idiom — the only casts are object-pointer casts, which are
well-defined.

### 5. Warning surface (`-Werror` discipline)

```
-Wall -Wextra -Werror -Wformat=2 -Wshadow -Wpointer-arith -Wcast-qual
-Wcast-function-type -Wstrict-prototypes -Wmissing-prototypes
-Wno-unused-parameter -fstack-protector-strong
```

- `-Wmissing-prototypes` forces every non-static function to be declared in
  `torx.h` — this is how the *export surface* stays intentional: anything
  accidentally left non-static shows up as a warning, and later as an
  unexpected `nm -D` export.
- Missed `<time.h>` / `<netdb.h>` (clock_gettime / `struct addrinfo`) were
  real breakages; both are in `torx.c` now.

### 6. Export surface is inspected, not assumed

`make check` asserts:

| assertion | why |
|---|---|
| `nm -D --defined-only` has `T connect` | the hook exists at all (`hook.export.connect`) |
| no `TEXTREL` in `readelf -d` | text relocations defeat RELRO-style hardening |
| `__stack_chk_fail` present | canaries actually emitted |
| `ldd -r` reports no undefined symbols | `LD_PRELOAD`'d libraries must resolve cleanly at load |
| DNS taxonomy | if `getaddrinfo` ever becomes exported the build prints an explicit note to update `LIMITATIONS.md §1` and the `dns.*` rows before trusting anything |

The leak harness goes further: `dns.export.getaddrinfo` and
`hook.export.connect` store the **complete** `nm -D --defined-only` text
symbol list as JSON evidence (`exported_T`), so a reviewer sees exactly what
the library exports in each recorded run. Today that list is one line —
`T connect`. `-Wmissing-prototypes` is what keeps it that way: any function
left non-static surfaces as a build warning before it ever becomes an export.

### 7. Toolchain realities on the reference host

- GCC 14.2, `-Werror` clean.
- `strace` and `nft` are **absent**. The leak harness is designed not to
  need either: the `TORX_PORT=1` trick makes interception observable as a
  failed connect (see `tests/leak/README.md`), so no syscall tracing and no
  packet capture are required for the CI gate.
- `gcc -static` works — needed by the `bypass.static_binary` probe.
- The tree is not always a git repo: `GIT_REV` falls back to `nogit`.

### 8. Sanitizer builds

`make asan` works, but ASan *itself* `LD_PRELOAD`s `libasan`. Do not stack it
with the shim when wrapping real applications (the loader picks one
`connect`); use it for unit-test binaries only.

## Reproducing the artifact

```sh
make            # libtorx.so
make check      # static assertions
make test       # tests/leak/run.sh — gates against LIMITATIONS.md
TORX_DEBUG=1 ./bin/torx curl -s https://check.torproject.org/api/ip
```

The last command must print `"IsTor": true`; the harness's `tor.e2e` row
asserts exactly that (3 attempts, non-gating).
