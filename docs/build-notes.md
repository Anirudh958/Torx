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
- `strace` is **absent**; `nft` exists but outside the default user `PATH`
  (`/usr/sbin/nft` — a failing `command -v nft` reads as absence; see the
  Phase-2 trial below). The leak harness needs neither: the `TORX_PORT=1`
  trick makes interception observable as a failed connect (see
  `tests/leak/README.md`), so no syscall tracing and no packet capture are
  required for the CI gate.
- `gcc -static` works — needed by the `bypass.static_binary` probe.
- The tree is not always a git repo: `GIT_REV` falls back to `nogit`.

### 8. Sanitizer builds

`make asan` works, but ASan *itself* `LD_PRELOAD`s `libasan`. Do not stack it
with the shim when wrapping real applications (the loader picks one
`connect`); use it for unit-test binaries only.

## Phase-2: can this host build a boundary?

`docs/harness.md` §6.1 requires the CI-capability question to be
*measured*, never asserted: "Measured by one throwaway workflow (or local
`unshare` trial) before any CI wiring is written; until then CI wiring is
deferred, not designed." The local half of that measurement happened on
2026-10-01, before any `netns/` code existed. (The first pass got `nft`
wrong: `command -v nft` failing was a `PATH` gap, not an absence. The
table below is the corrected measurement — kept honest rather than tidy.)

| check | result | how |
|---|---|---|
| unprivileged user namespaces | **yes** | `sysctl kernel.unprivileged_userns_clone` = 1; `unshare -Urn id` → `uid=0` in a fresh userns+netns |
| veth + addressing + default route inside a userns netns | **yes** | `ip link add … type veth`, `addr add`, `route add default` all succeeded inside `unshare -Urn` |
| `nft` — full child-side ruleset | **yes** | binary at `/usr/sbin/nft` (v1.1.3), **outside a normal user `PATH`** — `command -v nft` fails while `/usr/sbin/nft` works. Inside `unshare -Urn`: `table inet` + a nat chain with `dnat ip to …` + a `filter` chain with policy drop, listed back via `nft list ruleset` |
| `ip`, `tc`, `jq`, `timeout` | present | `/usr/bin/ip`, `/usr/sbin/tc` (also `PATH`-gapped), verified by use |
| `clang` | present, versioned | `/usr/bin/clang-18` and `/usr/lib/llvm-18/bin/clang` — no unversioned `clang` |
| `bpftool`, `strace` | **absent** | no binary anywhere — the cgroup-BPF attach needs its own loader (or libbpf), not just a compiler |
| child cgroup creation (own subtree) | **yes** | systemd delegates the invoking cgroup to uid 1000 (`user.slice/user-1000.slice/user@1000.service/…`); `mkdir` inside it succeeds, `mkdir` at the cgroup root does not |
| `bpf()` — `BPF_PROG_LOAD` probe | **EPERM** | `kernel.unprivileged_bpf_disabled=2`; probed as the unprivileged user *and* as userns root (`unshare -Ur`): errno 1 both times — load/attach needs init-ns capability, so a loader would not have been enough either |
| Tor listeners | **socks only** | `127.0.0.1:9050` answers; TransPort (9040) and DNSPort (5353) absent — empty torrc, defaults. Reference mode's step 1 would fail-closed here until a deployment configures them (`enforcement.md` §5); lab mode never depends on them |
| `CAP_NET_RAW` | no | same absence the leak harness records; pcap stays out of verdicts (`docs/harness.md` §7) |

Consequences, recorded as found:

- **The entire child-side boundary builds unprivileged on this host** —
  namespace, veth, addressing, route, inet nat+filter with DNAT and
  default drop, verification listing, plus the child's own cgroup
  (systemd delegates it). Two halves stay out of reach without init-ns
  privilege: the **cgroup-BPF attach** — `bpf()` returns `EPERM` for the
  unprivileged user *and* for userns root, so the missing piece was
  never just the loader; and the **path from an unprivileged child
  netns to the host's Tor** — a veth end cannot be moved into the host
  network namespace without privilege there, and no other link exists.
  The topology question over `docs/enforcement.md` §2 is resolved as
  `docs/harness.md` §6's open question 4 (decision, before `netns/` was
  written): two modes, lab first — `enforcement.md` §2.1 defines the
  privileged reference mode and the unprivileged lab mode, §5 step 6
  scopes the sensor attach, and both unreachable halves record
  `UNTESTED (reason:)` until a reference-mode run exists.
- `tests/enforce`'s `boundary.up` row computes the prerequisites at run
  time and reports `UNTESTED (reason:)` naming each unmet one — never
  silently green, never falsely red (`docs/harness.md` §4).
- **CI half: measured 2026-10-02.** A throwaway `capability-probe`
  workflow (the probe script is preserved in git history at commit
  `1e1d422`) ran once on a GitHub-hosted `ubuntu-latest` runner
  (`Linux-6.17.0-1022-azure-x86_64`, uid 1001, `CapEff=0`); the file
  was deleted after the answer landed here, per `harness.md` §6.1
  ("measure → record → retire"). Results, against the local column
  above:

  | check | runner | local |
  |---|---|---|
  | unprivileged user namespaces | **no** — `unshare -Urn true` fails `write /proc/self/uid_map: Operation not permitted` despite `unprivileged_userns_clone=1` and `max_user_namespaces=63838` (a restriction the probe did not separately attribute) | yes |
  | veth inside a userns | no — dies at the same `uid_map` write | yes |
  | `nft` binary | present: `/usr/sbin/nft` **v1.0.9** (older than local v1.1.3); `/usr/sbin` already on the runner's `PATH` | v1.1.3, PATH-gapped |
  | `nft list ruleset`, no caps | `EPERM` (cache init) — identical to local | same |
  | `nft` inside userns | no (userns prerequisite) | yes |
  | `bpf()` | `kernel.unprivileged_bpf_disabled=2`, `CapEff=0`; the `BPF_MAP_CREATE` probe returned `EINVAL` (attr validation answers before the privilege check — the sysctl is the authoritative fact) | `EPERM` on `BPF_PROG_LOAD` |
  | loopback TCP (bind/listen/connect) | **yes**, rc 0 | yes |
  | Tor | absent: no `tor` binary, `127.0.0.1:9050` refused | socks only |
  | tool belt | `gcc`, `make`, `jq`, `ip`, `nc`, `python3`, `nsenter`, `bpftool` all present | see table above |

  Consequences, recorded as found: static `tests/enforce` (source-audit
  rows, guard/gate, `make check`) is fully CI-viable. Every row that
  runs the launcher — `boundary.up`, and with it `disable.*`,
  `coverage.*`, through-boundary `control.*` — must record
  `UNTESTED (reason:)` on this runner: the boundary cannot be built
  there (userns blocked) and there is no Tor to reach either.
  `UNTESTED` never fails the gate, so CI can go green on statics alone
  while the dynamic half stays honestly black. The runner *can* host
  loopback-only rows, which is what makes the `control.*` floor row
  the one dynamic row with real CI reach. CI wiring for `tests/enforce`
  stays deferred until there are `signal.*`/`control.*` rows to wire —
  the capability question §6.1 gated on is now answered.
  **Wired 2026-10-02, same chunk that landed those rows:** the static
  job runs `./tests/enforce/run.sh --static` (the `signal.*` source
  audits — no boundary, no network); the floor row records wherever
  dynamic mode runs.

## Q2: can the observer read the child's nft counters?

`docs/harness.md` §6.2 asked whether an observer *outside* the boundary
can read live counters from the child ruleset — the dynamic evidence
the `agreement.*` rows would want. Measured 2026-10-02 locally: a
child created by `unshare -Urn` applied a `counter` rule and slept;
the observer (uid 1000, init user namespace, `CapEff=0`) then tried
every read path:

| path | result |
|---|---|
| `nft -j list ruleset` from the host netns | `EPERM` — cache initialization refused |
| `nsenter -t <child> -n nft …` (child netns only) | `EPERM` at `setns` — needs `CAP_SYS_ADMIN` in the owning userns |
| `nsenter -U -n …` and `nsenter -U -n -r …` | `EPERM` at `setgroups` — never reaches `nft` |
| raw `setns(netns_fd, CLONE_NEWNET)` via python | `EPERM` (errno 1) |
| `nft -j list ruleset` *inside* the userns | **rc 0** — full JSON, counter rule listed |

The child itself ran with `CapEff=000001ffffffffff` inside its own
userns. Conclusion: **no counter read is possible from outside the
userns** — every path requires the capability set that exists only
inside it. `agreement.*` rows therefore cannot lean on live observer
reads; §6.2's fallback order stands (a launcher-produced counter
snapshot is corroboration only — the boundary reporting on itself,
the P3 sin — and rows that cannot avoid it record
`UNTESTED (reason:)`).

## Reproducing the artifact

```sh
make            # libtorx.so
make check      # static assertions
make test       # tests/leak/run.sh — gates against LIMITATIONS.md
TORX_DEBUG=1 ./bin/torx curl -s https://check.torproject.org/api/ip
```

The last command must print `"IsTor": true`; the harness's `tor.e2e` row
asserts exactly that (3 attempts, non-gating).
