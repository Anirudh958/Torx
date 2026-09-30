# Why not torsocks?

This document answers the obvious objection: *if routing a process through
Tor with `LD_PRELOAD` is the wrong primitive, why not simply use
[torsocks](https://github.com/dgoulet/torsocks), which has shipped for
over a decade and knows every edge case already?*

Short answer: **you usually should.** torsocks is better at being an
`LD_PRELOAD` shim than anything in this tree. The question this repository
exists to answer is not *which shim is best*, but *what is wrong with the
shim class* — and that answer is architectural, not incremental.

## What torsocks gets right

A generous ledger, because the critiques below are of the mechanism, not
of the engineers who worked within it:

- **Fail-closed on the protocols it cannot carry.** From the
  [README](https://github.com/dgoulet/torsocks): torsocks "explicitly
  rejects any traffic other than TCP"; if it "detects any communication
  that can't go through the Tor network such as UDP traffic, for
  instance, the connection is denied"; and "if, for any reason, there is
  no way for torsocks to provide the Tor anonymity guarantee to your
  application, torsocks will force the application to quit and stop
  everything." A denied connection is a *loud* failure. The user learns
  their UDP app does not work; they do not learn that it is leaking, and
  it is not.
- **DNS handled where it can be.** Intercepted `gethostbyname` family
  calls are rerouted through Tor; the man page records the boundaries
  honestly (ISC `res_*` API unsupported, `torsocks(8)` LIMITATIONS).
- **The boundaries are documented, not discovered.** Static binaries,
  non-ELF executables, raw `syscall()`/`int 0x80` — all listed under
  KNOWN ISSUES/LIMITATIONS rather than left as surprises
  ([torsocks(8)](https://man.archlinux.org/man/torsocks.8)).
- **`torify(1)` was deprecated *toward* it**, not away from it: "provided
  for backward compatibility; instead you should use torsocks"
  ([torify(1)](https://manpages.debian.org/testing/tor/torify.1.en.html)).

Compare the thesis rows in [`LIMITATIONS.md`](../LIMITATIONS.md): TORX
denies nothing and quits nothing. Its UDP sockets *succeed* while
carrying the wrong payload (`udp.silent_misdelivery`, REFUTED), and its
QUIC client *succeeds* while going direct (`udp.quic.bypass`, REFUTED).
Same LD_PRELOAD constraint, opposite failure polarity: where torsocks
fails closed, an unmeasured shim fails open — which is exactly why the
taxonomy had to be measured rather than assumed.

## The taxonomy: where does the interception sit?

| Lineage | Who intercepts | What it can see | Inherent failure mode |
|---|---|---|---|
| **1. Interpose on libc** | `LD_PRELOAD` symbol binding, inside the process | only what the app asks libc to do | **silent fail-open**: any path that does not go through an intercepted symbol (raw syscalls, static binaries, an unhooked syscall like `sendto`) is invisible — the shim believes it is complete, the bytes go direct |
| **2. Own the routing table** | kernel: network namespace + nftables + cgroup policy | every packet the process emits, regardless of how the process produced it | **fail-closed by construction**: default-deny rules; traffic that does not match a redirect is dropped, not passed |

The two lineages are not competing implementations of one idea. They are
different *places to stand*, and everything else follows from the place.

### Lineage 1: torsocks, proxychains-ng, torify — and TORX legacy

All four hook libc from inside the process. The class-wide properties,
each admitted by the tools themselves:

- **The preload mechanism is a documented hope, not a guarantee.**
  torsocks' own README: "if the application is not using the libc or for
  instance uses raw syscalls, torsocks will be useless and the traffic
  will not go through Tor." That is the same failure as TORX's
  `bypass.raw_syscall` row — measured here, admitted there, unavoidable
  everywhere in this lineage. `LD_PRELOAD` is also inert for setuid/
  setgid binaries (secure-execution mode; `torify(1)` states plainly
  "since both method use LD_PRELOAD, torify cannot be applied to suid
  binaries"), and can be dropped by any `env -i`, a cleared environment,
  or a service unit that does not set it.
- **TCP-only is the accepted contract of the lineage.**
  [proxychains-ng](https://github.com/rofl0r/proxychains-ng/blob/master/README):
  "It supports TCP only (no UDP/ICMP etc)." torsocks(8): "Outgoing TCP
  connections can only be proxified." UDP, QUIC, ICMP, raw packets: out
  of scope of the mechanism, and their behaviour under the shim becomes a
  property of the individual program rather than of the anonymizer.
- **The lineage's own authors recommend the other lineage when it
  matters.** The proxychains-ng README, verbatim: *"The way it works is
  basically a HACK; so it is possible that it doesn't work with your
  program... If your program doesn't work with proxychains, consider
  using an iptables based solution instead; this is much more robust."*
  An iptables-based solution *is* the network-namespace answer: steer by
  route, not by hook. The engineering papers over the seam say so in
  their first paragraph.

So: torsocks is the best possible member of a lineage whose ceiling is
"fail loudly on everything it can see, be blind to everything it cannot."
You cannot patch your way across that boundary — no symbol table contains
`syscall`.

### Lineage 2: Tails, Whonix, Qubes — and Phase-2 netns

The mature anonymization systems do not ask the process for permission:

- **[Tails](https://tails.net/)** runs Tor system-wide and forces all
  outgoing traffic through it with firewall/policy routing — a host
  decision, not a per-process one.
- **[Whonix](https://www.whonix.org/)** splits the workstation from a
  Tor gateway VM; the workstation has *no* route to the network except
  through the gateway, and the gateway fails closed if Tor is down.
  Isolation by construction: the dangerous path does not exist to be
  taken.
- **[Qubes OS](https://www.qubes-os.org/)** plus Whonix templates
  adds compartmentalization: one wrong app is confined to its qube's
  netvm, which is itself a Tor gateway.
- **Tor's transparent-proxy ports** (`TransPort`, `DNSPort`, `NATDPort`
  in [tor(1)](https://manpages.debian.org/testing/tor/tor.1.en.html))
  exist precisely so that a *firewall* can redirect traffic from
  processes that never agree to cooperate — the kernel hands the packet
  to Tor regardless of what libc was asked to do.

None of these care whether the app is statically linked, speaks raw
`sendto`, or uses QUIC. The network namespace sees every packet because
packets are the namespace's native vocabulary. A `sendto` the process
never told anyone about still crosses nftables rules.

## Why TORX is in lineage 1 anyway

Because it is a **control group**, not a product. `THREAT_MODEL.md` §7
plans the Phase-2 architecture as *netns + cgroup-v2 BPF + nftables,
fail-closed*; a scientific claim that the shim class is wrong needs a
measured baseline of *how* it is wrong. torsocks fails closed and
therefore teaches us little about the failure modes a shim can hide —
you need a shim that fails open, under test, to surface them:

- which syscalls are outside the hook set (`udp.export.sendto`),
- what happens to a socket the shim corrupts (`udp.fd_swap`,
  `udp.silent_misdelivery` — no errno, ever),
- what the shim never sees at all (`udp.quic.bypass`,
  `ipv6.passthrough`, `bypass.raw_syscall`),
- and what a defender can still detect despite all of it
  ([`DETECTION.md`](../DETECTION.md)).

The 18 rows in `tests/leak/results.jsonl` are the experiment; the netns
tree that supersedes this shim is the conclusion it earns. Until that
tree exists (see [`SECURITY.md`](../SECURITY.md)), this artifact's leaks
are documented by design and will not be patched.

## The correct primitive

Do not interpose on the process's *library calls*; interpose on its
*route*. Put the process in a network namespace, let cgroup membership
decide who gets the namespace, and let nftables decide where packets may
go: default drop, explicit redirect of TCP/DNS to Tor's transparent
ports, explicit handling (or deliberate drop) of UDP and ICMP. The
properties then follow from the kernel's own semantics rather than from
which symbols the application chose to call:

- **static vs. dynamic linking** stops being a security property,
- **`syscall()` vs `connect()`** stops being a security property,
- **QUIC vs TCP** stops being a blind spot, and
- **failure** becomes *packet dropped*, which is the same verb torsocks
  wishes it could use for every path.

The shim in this repository was the wrong primitive. torsocks is the best
shim. Neither is the architecture.

## Citations

### Primary engineering sources

- torsocks README and man pages —
  [github.com/dgoulet/torsocks](https://github.com/dgoulet/torsocks),
  [torsocks(8)](https://man.archlinux.org/man/torsocks.8),
  [torsocks(1)](https://man.archlinux.org/man/torsocks.1)
- proxychains-ng README (v4.17) —
  [github.com/rofl0r/proxychains-ng](https://github.com/rofl0r/proxychains-ng/blob/master/README)
- torify(1), Tor Project (Peter Palfrader, Jacob Appelbaum) —
  [manpages.debian.org](https://manpages.debian.org/testing/tor/torify.1.en.html)
- tor(1) —
  [manpages.debian.org](https://manpages.debian.org/testing/tor/tor.1.en.html)
- `LD_PRELOAD` / secure-execution mode —
  [ld.so(8)](https://man.archlinux.org/man/ld.so.8)
- Tails, Whonix, Qubes OS home documentation —
  [tails.net](https://tails.net/),
  [whonix.org](https://www.whonix.org/),
  [qubes-os.org](https://www.qubes-os.org/)

### Academic work

*(Intentionally empty, as of 2026-09-30.)* No peer-reviewed evaluation
of the `LD_PRELOAD`-wrapper anonymizer class — comparing wrapper
fail-open/fail-closed rates against route-based enforcement — was found
while writing this document. The circumvention-measurement literature
studies censorship resilience and traffic analysis; it does not grade
shims. `THREAT_MODEL.md` §7 item 4 (*leak rate: legacy vs. torsocks vs.
netns*) is this repository's proposal for that experiment. A citation
here that we had not read would be worse than a visibly empty section;
if you know of adjacent work, open an issue.
