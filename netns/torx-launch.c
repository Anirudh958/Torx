/* netns/torx-launch — fail-closed boundary launcher (Phase 2, chunk 6b)
 *
 * Spec: docs/enforcement.md §5 (launch sequence), §2.1 (reference/lab
 * modes), §2 (topology). tests/enforce/run.sh runs this once with
 * /bin/true as the target; the exit code plus the JSON report are what
 * the boundary.up precondition row records.
 *
 * Contract:
 *   torx-launch [--mode=auto|lab|reference] [--report FILE] -- cmd [args...]
 *
 *   Exit 0..125  launch completed §5 and the target exited N; the code is
 *                the target's. A target killed by signal N exits 128+N
 *                (shell convention).
 *   Exit 70      launcher abort (EX_SOFTWARE) — report.step/report.reason
 *                say where; fail-closed, teardown always runs. A target
 *                that itself exits 70 is a completed launch: the report's
 *                status field, not the exit code, is authoritative.
 *   Exit 64      usage error (EX_USAGE), before any state exists.
 *
 * The launch is synchronous and crash-safe by construction: every
 * artifact (netns, veth, rules, cgroup) lives in namespaces owned by
 * this process or dies with it — in lab mode a SIGKILL leaves nothing
 * behind; reference mode teardown deletes explicitly.
 *
 * Pipe protocol (child -> parent): 'N' netns ready · 'C' child side
 * configured · '3' ruleset applied+verified · '5' re-verified · '7'
 * drops complete · 'X' at the exec point · 'F'/'E' + reason line.
 * (parent -> child): 'V' release the veth · 'R' re-verify · 'S' step 6
 * done, take your drops · '9' exec now. Every byte is one protocol
 * message; CLOEXEC makes a successful exec close the channel, which is
 * how 'EOF after X' is read as "target is running".
 *
 * Report JSON invariant: every string this program emits is authored
 * here (literals, errno text, paths read from procfs) and sanitized —
 * quotes, backslashes and control bytes become '_' at the two call
 * sites that format (step_done, set_fail) — so the report is written
 * directly without an escaping layer. Adding a dynamic string means
 * keeping it inside those paths or adding escaping first.
 *
 * §5 numbering is what the report records; the fork that hosts the child
 * netns happens inside step 2 (something must hold N2 to receive the
 * veth peer), but the security-relevant order holds: no target process
 * exists until step 9, and the capability drop completes first.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/capability.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define GW        "10.187.0.1"
#define GW_CHILD  "10.187.0.2"
#define VETH_H    "veth-torx-h"
#define VETH_C    "veth-torx-c"
#define PORT_SOCKS 9050
#define PORT_TRANS 9040
#define PORT_DNS   5353
#define TABLE_CHILD "torx"
#define TABLE_BACKSTOP "torx_b"
#define PROBE_MS  2000

#define EXIT_ABORT 70
#define EXIT_USAGE 64

#define STR2(x) #x
#define STR(x)  STR2(x)
#define PORT_TRANS_STR STR(PORT_TRANS)
#define PORT_DNS_STR   STR(PORT_DNS)

/* Child ruleset (docs/enforcement.md §6). Hooks: output — every packet
 * the wrapped process can produce is locally originated; the child never
 * forwards (one veth, no other interface), so a prerouting hook would be
 * dead code and a rule that is never applied counts as absent (§5 step 5).
 * Both rulesets verified byte-for-byte against this host's nft (see
 * docs/build-notes.md): priority names, nfproto guard, dport set. */
static const char CHILD_RULES[] =
    "table inet " TABLE_CHILD " {\n"
    "\tchain nat_out {\n"
    "\t\ttype nat hook output priority dstnat; policy accept;\n"
    "\t\tmeta oifname \"lo\" accept\n"
    "\t\tip daddr " GW " accept\n"
    "\t\tmeta nfproto ipv4 meta l4proto tcp dnat ip to " GW ":" PORT_TRANS_STR "\n"
    "\t\tmeta nfproto ipv4 udp dport 53 dnat ip to " GW ":" PORT_DNS_STR "\n"
    "\t}\n"
    "\tchain filter_out {\n"
    "\t\ttype filter hook output priority filter; policy drop;\n"
    "\t\tct state established,related accept\n"
    "\t\tmeta oifname \"lo\" accept\n"
    "\t\tip daddr " GW " accept\n"
    "\t}\n"
    "}\n";

/* Trusted-side backstop (§3 mechanism 3): "from veth, accept only
 * {9040,5353}; drop everything else" — scoped to the veth, so the
 * trusted side's own policy stays accept in reference mode (the host
 * must not lose its input) and the claim reads identically in both. */
static const char BACKSTOP_RULES[] =
    "table inet " TABLE_BACKSTOP " {\n"
    "\tchain guard {\n"
    "\t\ttype filter hook input priority filter; policy accept;\n"
    "\t\tiifname \"lo\" accept\n"
    "\t\tiifname \"" VETH_H "\" tcp dport { " PORT_TRANS_STR ", " PORT_DNS_STR " } accept\n"
    "\t\tiifname \"" VETH_H "\" udp dport { " PORT_TRANS_STR ", " PORT_DNS_STR " } accept\n"
    "\t\tiifname \"" VETH_H "\" drop\n"
    "\t}\n"
    "}\n";

/* ---- report ------------------------------------------------------------ */

#define MAX_STEPS 9
#define REASON_MAX 400
#define DETAIL_MAX 300

struct step_rec {
    int n;
    const char *name;
    char status[12];
    char detail[DETAIL_MAX];
};

static struct step_rec g_steps[MAX_STEPS];
static int g_nsteps;
static int g_step;                 /* current step, for failures */
static char g_reason[REASON_MAX];
static const char *g_mode = "lab";
static const char *g_mode_reason = "";
static char g_sensor[DETAIL_MAX];
static char g_cgroup[320];
static int g_target_exit = -1;
static const char *g_report_path;
static pid_t g_cpid = -1;
static uid_t g_rid;                /* invoking uid, captured before unshare */
static char **g_argv_target;
static volatile sig_atomic_t g_stopped;

static void step_done(int n, const char *name, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
static void set_fail(int step, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* The report invariant lives here: one sanitization point for every
 * string that reaches emit_report through these two formatters. */
static void json_sanitize(char *s)
{
    size_t i;
    for (i = 0; s[i]; i++) {
        if (s[i] == '"' || s[i] == '\\' || (unsigned char)s[i] < 0x20)
            s[i] = '_';
    }
}

static void step_done(int n, const char *name, const char *fmt, ...)
{
    struct step_rec *s;
    va_list ap;
    if (g_nsteps >= MAX_STEPS)
        return;
    s = &g_steps[g_nsteps++];
    s->n = n;
    s->name = name;
    snprintf(s->status, sizeof s->status, "ok");
    va_start(ap, fmt);
    vsnprintf(s->detail, sizeof s->detail, fmt, ap);
    va_end(ap);
    json_sanitize(s->detail);
}

static void set_fail(int step, const char *fmt, ...)
{
    va_list ap;
    g_step = step;
    va_start(ap, fmt);
    vsnprintf(g_reason, sizeof g_reason, fmt, ap);
    va_end(ap);
    json_sanitize(g_reason);
}

static void emit_report(const char *status)
{
    FILE *f;
    int i;
    if (!g_report_path || !g_report_path[0])
        return;
    f = fopen(g_report_path, "w");
    if (!f)
        return;
    fprintf(f, "{\"report_schema\":1,\"mode\":\"%s\",\"mode_reason\":\"%s\"",
            g_mode, g_mode_reason);
    fprintf(f, ",\"status\":\"%s\"", status);
    if (strcmp(status, "ok") == 0) {
        fprintf(f, ",\"target_exit\":%d", g_target_exit);
    } else {
        fprintf(f, ",\"step\":%d,\"reason\":\"%s\"", g_step, g_reason);
    }
    fprintf(f, ",\"sensor\":\"%s\",\"cgroup\":\"%s\"", g_sensor, g_cgroup);
    fprintf(f, ",\"steps\":[");
    for (i = 0; i < g_nsteps; i++) {
        fprintf(f, "%s{\"n\":%d,\"name\":\"%s\",\"status\":\"%s\",\"detail\":\"%s\"}",
                i ? "," : "", g_steps[i].n, g_steps[i].name,
                g_steps[i].status, g_steps[i].detail);
    }
    fprintf(f, "]}");
    fclose(f);
}

/* ---- small helpers ----------------------------------------------------- */

static int write_str(const char *path, const char *s)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    size_t len = strlen(s);
    ssize_t w;
    if (fd < 0)
        return -1;
    w = write(fd, s, len);
    close(fd);
    return (w == (ssize_t)len) ? 0 : -1;
}

/* fork+exec, inherit stdio, return child's exit status (or 127..255) */
static int run_argv(char *const argv[])
{
    pid_t p;
    int st = 0;
    p = fork();
    if (p < 0)
        return -1;
    if (p == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }
    if (waitpid(p, &st, 0) < 0)
        return -1;
    if (!WIFEXITED(st))
        return -1;
    return WEXITSTATUS(st);
}

/* same, with stdio silenced — for best-effort teardown, whose failures
 * (a veth pair already gone with the child's netns) must not pollute
 * the evidence stream */
static int run_argv_quiet(char *const argv[])
{
    pid_t p;
    int st = 0;
    p = fork();
    if (p < 0)
        return -1;
    if (p == 0) {
        int dn = open("/dev/null", O_RDWR);
        if (dn >= 0) {
            dup2(dn, STDIN_FILENO);
            dup2(dn, STDOUT_FILENO);
            dup2(dn, STDERR_FILENO);
            if (dn > STDERR_FILENO)
                close(dn);
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    if (waitpid(p, &st, 0) < 0)
        return -1;
    if (!WIFEXITED(st))
        return -1;
    return WEXITSTATUS(st);
}

/* fork+exec, capture stdout into buf (NUL-terminated), return exit status */
static int run_argv_out(char *const argv[], char *buf, size_t buflen)
{
    pid_t p;
    int st = 0, fd[2];
    size_t used = 0;
    if (buflen)
        buf[0] = '\0';
    if (pipe2(fd, O_CLOEXEC) < 0)
        return -1;
    p = fork();
    if (p < 0) {
        close(fd[0]);
        close(fd[1]);
        return -1;
    }
    if (p == 0) {
        close(fd[0]);
        dup2(fd[1], STDOUT_FILENO);
        close(fd[1]);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(fd[1]);
    for (;;) {
        ssize_t r;
        if (used + 1 >= buflen)
            break;
        r = read(fd[0], buf + used, buflen - used - 1);
        if (r > 0) {
            used += (size_t)r;
        } else if (r < 0 && errno == EINTR) {
            if (g_stopped) {
                kill(p, SIGKILL);
                break;
            }
            continue;
        } else {
            break;
        }
    }
    buf[used] = '\0';
    close(fd[0]);
    if (waitpid(p, &st, 0) < 0)
        return -1;
    if (!WIFEXITED(st))
        return -1;
    return WEXITSTATUS(st);
}

/* nft -f - with the ruleset on stdin — one transaction, all or nothing */
static int nft_apply(const char *rules)
{
    pid_t p;
    int st = 0, fd[2];
    const char *w;
    if (pipe2(fd, O_CLOEXEC) < 0)
        return -1;
    p = fork();
    if (p < 0) {
        close(fd[0]);
        close(fd[1]);
        return -1;
    }
    if (p == 0) {
        if (dup2(fd[0], STDIN_FILENO) < 0)
            _exit(99);
        if (fd[0] != STDIN_FILENO)
            close(fd[0]);
        close(fd[1]);
        execlp("nft", "nft", "-f", "-", (char *)NULL);
        _exit(127);
    }
    close(fd[0]);
    w = rules;
    while (*w) {
        ssize_t n = write(fd[1], w, strlen(w));
        if (n > 0) {
            w += n;
        } else if (n < 0 && errno == EINTR && !g_stopped) {
            continue;
        } else {
            break;
        }
    }
    close(fd[1]);
    if (waitpid(p, &st, 0) < 0)
        return -1;
    if (!WIFEXITED(st))
        return -1;
    return WEXITSTATUS(st);
}

/* §5 step 5: "present and active" — nft list must succeed (absent table
 * fails the command) and the JSON must contain applied rules; the apply
 * itself is one transaction, so partial application is not a state. */
static int nft_verify(const char *table)
{
    char out[8192];
    char tbuf[64];
    char *argv[] = { "nft", "-j", "list", "table", "inet", tbuf, NULL };
    snprintf(tbuf, sizeof tbuf, "%s", table);
    if (run_argv_out(argv, out, sizeof out) != 0)
        return -1;
    if (!strstr(out, "\"rule\""))
        return -1;
    return 0;
}

/* ---- mode selection (§2.1): a measurement, not a preference ------------- */

static bool have_cap_net_admin(void)
{
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct data[2];
    memset(&hdr, 0, sizeof hdr);
    memset(data, 0, sizeof data);
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid = 0;
    if (syscall(SYS_capget, &hdr, data) != 0)
        return false;
    return (data[0].effective & (1U << CAP_NET_ADMIN)) != 0;
}

/* unshare(CLONE_NEWUSER|CLONE_NEWNET) + the map dance: N1 exists, we are
 * root in the userns (full caps over N1 and, later, over N2). */
static int enter_lab(void)
{
    char buf[64];
    uid_t uid = getuid();
    gid_t gid = getgid();
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0)
        return -1;
    if (write_str("/proc/self/setgroups", "deny") != 0)
        return -1;
    snprintf(buf, sizeof buf, "0 %u 1", (unsigned)uid);
    if (write_str("/proc/self/uid_map", buf) != 0)
        return -1;
    snprintf(buf, sizeof buf, "0 %u 1", (unsigned)gid);
    if (write_str("/proc/self/gid_map", buf) != 0)
        return -1;
    return 0;
}

/* ---- step 1: Tor probe, scoped to what the mode claims ------------------ */

static int tcp_probe(const char *ip, int port, char *d, size_t dn)
{
    struct sockaddr_in a;
    struct pollfd pf;
    int s, r, err = 0;
    socklen_t elen = sizeof err;
    s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (s < 0) {
        snprintf(d, dn, "socket: %s", strerror(errno));
        return -1;
    }
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) {
        snprintf(d, dn, "inet_pton %s failed", ip);
        close(s);
        return -1;
    }
    r = connect(s, (struct sockaddr *)&a, sizeof a);
    if (r != 0 && errno == EINPROGRESS) {
        pf.fd = s;
        pf.events = POLLOUT;
        r = poll(&pf, 1, PROBE_MS);
        if (r <= 0) {
            snprintf(d, dn, "%s:%d no answer (%s)", ip, port,
                     r == 0 ? "timeout" : strerror(errno));
            close(s);
            return -1;
        }
        if (getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &elen) != 0)
            err = errno;
        if (err != 0) {
            snprintf(d, dn, "%s:%d no answer (%s)", ip, port, strerror(err));
            close(s);
            return -1;
        }
    } else if (r != 0) {
        snprintf(d, dn, "%s:%d no answer (%s)", ip, port, strerror(errno));
        close(s);
        return -1;
    }
    snprintf(d, dn, "%s:%d answers", ip, port);
    close(s);
    return 0;
}

static int probe_tor(void)
{
    char d[128];
    char all[DETAIL_MAX];
    bool reference = (strcmp(g_mode, "reference") == 0);
    all[0] = '\0';
    if (tcp_probe("127.0.0.1", PORT_SOCKS, d, sizeof d) != 0) {
        set_fail(1, "socks probe: %s", d);
        return -1;
    }
    snprintf(all, sizeof all, "socks %s", d);
    /* TransPort/DNSPort: reference mode's deployment prerequisite — their
     * absence here is measured (build-notes.md) and aborts fail-closed. */
    if (reference) {
        if (tcp_probe("127.0.0.1", PORT_TRANS, d, sizeof d) != 0) {
            set_fail(1, "trans probe (deployment prerequisite): %s", d);
            return -1;
        }
        snprintf(all + strlen(all), sizeof all - strlen(all), "; trans %s", d);
        if (tcp_probe("127.0.0.1", PORT_DNS, d, sizeof d) != 0) {
            set_fail(1, "dns probe (deployment prerequisite): %s", d);
            return -1;
        }
        snprintf(all + strlen(all), sizeof all - strlen(all), "; dns %s", d);
    } else {
        snprintf(all + strlen(all), sizeof all - strlen(all),
                 "; trans,dns skipped (lab scope, §2.1)");
    }
    step_done(1, "tor_probe", "%s", all);
    return 0;
}

/* ---- step 6: cgroup + bpf() probe --------------------------------------- */

static int read_cgroup_rel(char *rel, size_t relsz)
{
    FILE *f = fopen("/proc/self/cgroup", "r");
    char line[512];
    bool found = false;
    if (!f)
        return -1;
    while (fgets(line, sizeof line, f)) {
        char *p = strstr(line, "0::");
        if (p) {
            p += 3;
            line[strcspn(line, "\n")] = '\0';
            snprintf(rel, relsz, "%s", p);
            found = true;
            break;
        }
    }
    fclose(f);
    return found ? 0 : -1;
}

static int cgroup_setup(void)
{
    char rel[256];
    char procs[400];
    char pidbuf[32];
    char line[64];
    FILE *f;
    bool joined = false;
    pid_t me = getpid();

    if (g_cpid <= 0)
        return -1;
    if (read_cgroup_rel(rel, sizeof rel) != 0) {
        set_fail(6, "cannot read own cgroup path from /proc/self/cgroup");
        return -1;
    }
    if (rel[0] == '\0' || strcmp(rel, "/") == 0) {
        set_fail(6, "own cgroup is the root — no delegated subtree to mkdir in "
                    "(measured: delegation expected, build-notes.md)");
        return -1;
    }
    snprintf(g_cgroup, sizeof g_cgroup, "/sys/fs/cgroup%s/torx-%d",
             rel, (int)me);
    json_sanitize(g_cgroup);
    if (mkdir(g_cgroup, 0755) != 0) {
        if (errno != EEXIST || rmdir(g_cgroup) != 0 ||
            mkdir(g_cgroup, 0755) != 0) {
            set_fail(6, "mkdir %s: %s", g_cgroup, strerror(errno));
            return -1;
        }
    }
    snprintf(procs, sizeof procs, "%s/cgroup.procs", g_cgroup);
    snprintf(pidbuf, sizeof pidbuf, "%d\n", (int)g_cpid);
    if (write_str(procs, pidbuf) != 0) {
        set_fail(6, "join: write %d to %s: %s", (int)g_cpid, procs,
                 strerror(errno));
        return -1;
    }
    /* "present and active" — the write succeeded; read it back, because
     * a cgroup.procs write that reports success but moves nothing would
     * leave the target outside the sensor's reach. */
    f = fopen(procs, "r");
    if (f) {
        while (fgets(line, sizeof line, f)) {
            if (atoi(line) == (int)g_cpid) {
                joined = true;
                break;
            }
        }
        fclose(f);
    }
    if (!joined) {
        set_fail(6, "join: %d not visible in %s after the write", (int)g_cpid,
                 procs);
        return -1;
    }
    return 0;
}

/* §5 step 6: attempt bpf(); lab's declared EPERM is the scope boundary
 * (recorded, not failed); anything else — in either mode — aborts, and
 * reference mode additionally cannot proceed without the loader
 * (sensor attach lands with probes/). Returns 0 only when step 6 stands. */
static int bpf_probe_step(void)
{
    union bpf_attr attr;
    long r;
    bool reference = (strcmp(g_mode, "reference") == 0);
    memset(&attr, 0, sizeof attr);
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = 0;
    errno = 0;
    r = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof attr);
    if (r >= 0) {
        close((int)r);
        set_fail(6, "bpf() accepted an empty program — the loader that would "
                    "attach step 6 is not implemented (lands with probes/)");
        return -1;
    }
    if (errno == EPERM && reference) {
        set_fail(6, "bpf(): EPERM in reference mode — §5 step 6 attach is "
                    "required and cannot be skipped");
        return -1;
    }
    if (errno == EPERM) {
        snprintf(g_sensor, sizeof g_sensor,
                 "eperm-declared-scope (kernel.unprivileged_bpf_disabled=2, "
                 "build-notes.md)");
        step_done(6, "sensor_cgroup",
                  "cgroup %s joined; bpf() EPERM — declared scope boundary "
                  "(§2.1)", g_cgroup);
        return 0;
    }
    if (reference) {
        set_fail(6, "bpf(): %s — reference mode needs the attach, and the "
                    "loader lands with probes/", strerror(errno));
        return -1;
    }
    set_fail(6, "bpf(): %s — lab's declared boundary is EPERM (§2.1); this "
                "host permits program load but the loader is not implemented",
             strerror(errno));
    return -1;
}

/* ---- pipe protocol ------------------------------------------------------ */

static int sendb(int fd, char c)
{
    for (;;) {
        ssize_t n = write(fd, &c, 1);
        if (n == 1)
            return 0;
        if (n < 0 && errno == EINTR && !g_stopped)
            continue;
        return -1;
    }
}

static int recvb(int fd, char *c)
{
    for (;;) {
        ssize_t n = read(fd, c, 1);
        if (n == 1)
            return 0;
        if (n < 0 && errno == EINTR && !g_stopped)
            continue;
        if (n < 0 && g_stopped)
            return -2;
        return -1; /* EOF or stopped */
    }
}

static int recv_line(int fd, char *buf, size_t len)
{
    size_t used = 0;
    if (len)
        buf[0] = '\0';
    for (;;) {
        char c;
        ssize_t n = read(fd, &c, 1);
        if (n == 1) {
            if (c == '\n') {
                buf[used] = '\0';
                return 0;
            }
            if (used + 1 < len)
                buf[used++] = c;
            continue;
        }
        if (n < 0 && errno == EINTR && !g_stopped)
            continue;
        buf[used] = '\0';
        return used ? 0 : -1;
    }
}

/* parent: read one child status byte; 'F' (or 'E') carries a line */
static int expect_status(int fd, char want, int step, const char *what)
{
    char c, line[240];
    int r = recvb(fd, &c);
    if (r == -2) {
        set_fail(step, "interrupted");
        return -1;
    }
    if (r != 0) {
        set_fail(step, "child died before %s", what);
        return -1;
    }
    if (c == want)
        return 0;
    if (c == 'F' || c == 'E') {
        recv_line(fd, line, sizeof line);
        set_fail(step, "child: %s", line[0] ? line : what);
        return -1;
    }
    set_fail(step, "unexpected child status 0x%02x during %s",
             (unsigned char)c, what);
    return -1;
}

/* parent after '9'. 'X' says the helper reached the exec point; EOF next
 * means CLOEXEC closed the channel (target running), 'E'+line means exec
 * failed. A helper that dies without 'X' is a launch failure, not a
 * target outcome — that distinction is what keeps step 9 fail-closed. */
static int await_exec(int fd)
{
    char c = 0, line[240];
    int r = recvb(fd, &c);
    if (r == -2) {
        set_fail(9, "interrupted");
        return -1;
    }
    if (r != 0) {
        set_fail(9, "child died before exec");
        return -1;
    }
    if (c != 'X') {
        if (c == 'E' || c == 'F') {
            recv_line(fd, line, sizeof line);
            set_fail(9, "child: %s", line[0] ? line : "status before exec");
        } else {
            set_fail(9, "unexpected child status 0x%02x before exec",
                     (unsigned char)c);
        }
        return -1;
    }
    r = recvb(fd, &c);
    if (r == -2) {
        set_fail(9, "interrupted");
        return -1;
    }
    if (r != 0)
        return 0; /* EOF: exec closed the channel — the target is running */
    if (c == 'E' || c == 'F') {
        recv_line(fd, line, sizeof line);
        set_fail(9, "exec: %s", line[0] ? line : "target exec failed");
        return -1;
    }
    set_fail(9, "unexpected child status 0x%02x after exec", (unsigned char)c);
    return -1;
}

/* ---- lifecycle ---------------------------------------------------------- */

static void reap_helper(void)
{
    if (g_cpid <= 0)
        return;
    kill(g_cpid, SIGKILL);
    while (waitpid(g_cpid, NULL, 0) < 0 && errno == EINTR)
        ;
    g_cpid = -1;
}

static int wait_target(int *stp)
{
    for (;;) {
        pid_t r = waitpid(g_cpid, stp, 0);
        if (r == g_cpid)
            return 0;
        if (r < 0 && errno == EINTR) {
            if (g_stopped) {
                kill(g_cpid, SIGKILL);
                while (waitpid(g_cpid, stp, 0) < 0 && errno == EINTR)
                    ;
                return -1;
            }
            continue;
        }
        return -1;
    }
}

/* Fail-closed teardown: everything this launch created in the trusted
 * side goes away whether §5 completed or aborted. In lab mode N1 dies
 * with this process anyway; explicit deletion keeps reference mode
 * (host netns) and partial runs byte-identical. The child's table and
 * netns are owned by the helper/target and die with it. */
static void teardown(void)
{
    char *del_veth[] = { "ip", "link", "del", VETH_H, NULL };
    run_argv_quiet((char *[]){ "nft", "delete", "table", "inet",
                               TABLE_BACKSTOP, NULL });
    run_argv_quiet(del_veth);
    if (g_cgroup[0])
        rmdir(g_cgroup);
}

static void on_stop(int sig)
{
    (void)sig;
    g_stopped = 1;
}

static void install_signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_stop;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; /* no SA_RESTART: EINTR is how aborts notice */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN); /* a dead peer is a protocol error, not death */
}

/* nft lives in /usr/sbin on Debian-derivatives — execvp would miss it */
static void extend_path(void)
{
    const char *p = getenv("PATH");
    char buf[1024];
    if (!p || !p[0])
        p = "/usr/bin:/bin";
    if (strstr(p, "/usr/sbin"))
        return;
    snprintf(buf, sizeof buf, "%s:/usr/sbin:/sbin", p);
    setenv("PATH", buf, 1);
}

static void usage(void)
{
    fprintf(stderr,
            "usage: torx-launch [--mode=auto|lab|reference] [--report FILE]"
            " -- cmd [args...]\n");
    exit(EXIT_USAGE);
}

/* ---- the child ---------------------------------------------------------- */

/* The target runs as the invoking uid. In lab mode the userns maps our
 * uid 0 back to that uid — a map check, not a setuid, because only uid 0
 * exists inside the map. Reference mode starts as the invoking uid. */
static bool uid_ok(void)
{
    FILE *f;
    unsigned inner, outer, cnt;
    if (getuid() == g_rid)
        return true;
    f = fopen("/proc/self/uid_map", "r");
    if (!f)
        return false;
    if (fscanf(f, "%u %u %u", &inner, &outer, &cnt) != 3) {
        fclose(f);
        return false;
    }
    fclose(f);
    return inner == (unsigned)getuid() && outer == (unsigned)g_rid && cnt >= 1;
}

/* Protocol: 'N' netns ready · 'C' child side configured · '3' ruleset
 * applied+verified · '5' re-verified · '7' drops complete · 'X' at the
 * exec point · 'F'/'E' + reason line. 'V','R','S','9' come from the
 * parent. This process becomes the target at execvp — there is never a
 * second process wearing the enforcement. */
static int child_main(int rd, int wr)
{
    char *ip_lo[] = { "ip", "link", "set", "lo", "up", NULL };
    char *ip_addr[] = { "ip", "addr", "add", GW_CHILD "/30", "dev", VETH_C, NULL };
    char *ip_up[] = { "ip", "link", "set", VETH_C, "up", NULL };
    char *ip_def[] = { "ip", "route", "add", "default", "via", GW, NULL };
    char c, msg[200];
    char outcome = 'F';
    int ex = EXIT_ABORT;

    if (unshare(CLONE_NEWNET) != 0) {
        snprintf(msg, sizeof msg, "unshare(CLONE_NEWNET): %s", strerror(errno));
        goto fail;
    }
    if (sendb(wr, 'N') != 0)
        goto dead;
    if (recvb(rd, &c) != 0 || c != 'V') {
        snprintf(msg, sizeof msg, "parent never released the veth");
        goto fail;
    }
    if (run_argv(ip_lo) != 0 || run_argv(ip_addr) != 0 ||
        run_argv(ip_up) != 0 || run_argv(ip_def) != 0) {
        snprintf(msg, sizeof msg, "child addressing or default route failed");
        goto fail;
    }
    if (sendb(wr, 'C') != 0)
        goto dead;

    if (nft_apply(CHILD_RULES) != 0 || nft_verify(TABLE_CHILD) != 0) {
        snprintf(msg, sizeof msg, "child ruleset apply or verify failed");
        goto fail;
    }
    if (sendb(wr, '3') != 0)
        goto dead;
    if (recvb(rd, &c) != 0 || c != 'R') {
        snprintf(msg, sizeof msg, "parent never reached step 5");
        goto fail;
    }
    if (nft_verify(TABLE_CHILD) != 0) {
        snprintf(msg, sizeof msg, "child ruleset re-verify failed");
        goto fail;
    }
    if (sendb(wr, '5') != 0)
        goto dead;

    if (recvb(rd, &c) != 0 || c != 'S') {
        snprintf(msg, sizeof msg, "parent never completed step 6");
        goto fail;
    }
    /* step 7 (drops): NNP first so nothing below can be undone or gained */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        snprintf(msg, sizeof msg, "PR_SET_NO_NEW_PRIVS: %s", strerror(errno));
        goto fail;
    }
    if (!uid_ok() &&
        (setresuid(g_rid, g_rid, g_rid) != 0 || getuid() != g_rid)) {
        snprintf(msg, sizeof msg,
                 "uid %u is not the invoking uid %u and uid_map does not map it",
                 (unsigned)getuid(), (unsigned)g_rid);
        goto fail;
    }
    {
        struct __user_cap_header_struct ch;
        struct __user_cap_data_struct cd[2];
        memset(&ch, 0, sizeof ch);
        memset(cd, 0, sizeof cd);
        ch.version = _LINUX_CAPABILITY_VERSION_3;
        ch.pid = 0;
        if (syscall(SYS_capset, &ch, cd) != 0) {
            snprintf(msg, sizeof msg, "capset: %s", strerror(errno));
            goto fail;
        }
    }
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
        snprintf(msg, sizeof msg, "PR_SET_DUMPABLE 0: %s", strerror(errno));
        goto fail;
    }
    if (sendb(wr, '7') != 0)
        goto dead;
    if (recvb(rd, &c) != 0 || c != '9') {
        snprintf(msg, sizeof msg, "parent never reached step 9");
        goto fail;
    }
    /* CLOEXEC: a successful exec must not inherit the protocol channel
     * (a failed exec keeps it open — that is how 'E' is reported). The
     * target also must not inherit our ignored SIGPIPE — exec keeps
     * ignored dispositions, so restore the default first. */
    fcntl(rd, F_SETFD, FD_CLOEXEC);
    fcntl(wr, F_SETFD, FD_CLOEXEC);
    signal(SIGPIPE, SIG_DFL);
    if (sendb(wr, 'X') != 0)
        goto dead;
    execvp(g_argv_target[0], g_argv_target);
    snprintf(msg, sizeof msg, "exec %s: %s", g_argv_target[0], strerror(errno));
    outcome = 'E';
    ex = 127;
fail:
    json_sanitize(msg);
    if (sendb(wr, outcome) == 0) {
        char line[240];
        ssize_t w;
        snprintf(line, sizeof line, "%s\n", msg);
        w = write(wr, line, strlen(line));
        (void)w;
    }
    _exit(ex);
dead:
    _exit(EXIT_ABORT);
}

/* ---- main --------------------------------------------------------------- */

int main(int argc, char **argv)
{
    const char *mode_arg = NULL;
    int i, p2c[2] = { -1, -1 }, c2p[2] = { -1, -1 }, st = 0;
    bool have_cap, lab;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            i++;
            break;
        }
        if (strncmp(argv[i], "--mode=", 7) == 0) {
            mode_arg = argv[i] + 7;
            if (strcmp(mode_arg, "auto") != 0 &&
                strcmp(mode_arg, "lab") != 0 &&
                strcmp(mode_arg, "reference") != 0)
                usage();
        } else if (strcmp(argv[i], "--report") == 0) {
            if (++i >= argc)
                usage();
            g_report_path = argv[i];
        } else if (strncmp(argv[i], "--report=", 9) == 0) {
            g_report_path = argv[i] + 9;
        } else {
            usage();
        }
    }
    if (i >= argc)
        usage();
    g_argv_target = &argv[i];
    g_rid = getuid();

    install_signals();
    extend_path();

    /* Mode first — §5 preamble: fixed and recorded before step 1. */
    have_cap = have_cap_net_admin();
    if (mode_arg && strcmp(mode_arg, "lab") == 0) {
        g_mode = "lab";
        g_mode_reason = "requested via --mode=lab";
    } else if (mode_arg && strcmp(mode_arg, "reference") == 0) {
        if (!have_cap) {
            set_fail(0, "reference mode requested without CAP_NET_ADMIN — a "
                        "measurement, not a preference (docs/enforcement.md §2.1)");
            emit_report("aborted");
            return EXIT_ABORT;
        }
        g_mode = "reference";
        g_mode_reason = "requested via --mode=reference";
    } else {
        g_mode = have_cap ? "reference" : "lab";
        g_mode_reason = have_cap
            ? "auto: CAP_NET_ADMIN present, reference scope claimed"
            : "auto: no CAP_NET_ADMIN, lab scope (docs/enforcement.md §2.1)";
    }
    lab = (strcmp(g_mode, "lab") == 0);

    /* step 1 — host netns: before lab's unshare isolates us from Tor */
    if (probe_tor() != 0)
        goto abort;

    /* step 2 — trusted side, child netns, veth, addressing */
    if (lab && enter_lab() != 0) {
        set_fail(2, "enter_lab: unshare(CLONE_NEWUSER|CLONE_NEWNET) or id map: %s",
                 strerror(errno));
        goto abort;
    }
    if (pipe2(p2c, O_CLOEXEC) != 0 || pipe2(c2p, O_CLOEXEC) != 0) {
        set_fail(2, "pipe2: %s", strerror(errno));
        goto abort;
    }
    g_cpid = fork();
    if (g_cpid < 0) {
        set_fail(2, "fork: %s", strerror(errno));
        goto abort;
    }
    if (g_cpid == 0) {
        close(p2c[1]);
        close(c2p[0]);
        _exit(child_main(p2c[0], c2p[1]));
    }
    close(p2c[0]);
    p2c[0] = -1;
    close(c2p[1]);
    c2p[1] = -1;

    if (expect_status(c2p[0], 'N', 2, "child netns creation") != 0)
        goto abort;
    {
        char *add[] = { "ip", "link", "add", VETH_H, "type", "veth",
                        "peer", "name", VETH_C, NULL };
        char *addr[] = { "ip", "addr", "add", GW "/30", "dev", VETH_H, NULL };
        char *up[] = { "ip", "link", "set", VETH_H, "up", NULL };
        char pidbuf[16];
        char *mv[] = { "ip", "link", "set", VETH_C, "netns", pidbuf, NULL };
        snprintf(pidbuf, sizeof pidbuf, "%d", (int)g_cpid);
        if (run_argv(add) != 0) {
            set_fail(2, "ip link add: veth pair create failed");
            goto abort;
        }
        if (run_argv(addr) != 0) {
            set_fail(2, "ip addr add %s/30 on %s failed", GW, VETH_H);
            goto abort;
        }
        if (run_argv(up) != 0) {
            set_fail(2, "ip link set %s up failed", VETH_H);
            goto abort;
        }
        if (run_argv(mv) != 0) {
            set_fail(2, "ip link set %s netns failed", VETH_C);
            goto abort;
        }
    }
    if (sendb(p2c[1], 'V') != 0) {
        set_fail(2, "cannot release the child's veth");
        goto abort;
    }
    if (expect_status(c2p[0], 'C', 2, "child addressing") != 0)
        goto abort;
    step_done(2, "trusted_side",
              "%s; veth %s/%s paired, host %s/30 up, child default via %s",
              g_mode, VETH_H, VETH_C, GW, GW);

    /* step 3 — child ruleset, installed inside N2 by the helper */
    if (expect_status(c2p[0], '3', 3, "child ruleset apply") != 0)
        goto abort;
    step_done(3, "child_rules", "nft apply + verify in child netns (table inet %s)",
              TABLE_CHILD);

    /* step 4 — backstop on the trusted side */
    if (nft_apply(BACKSTOP_RULES) != 0) {
        set_fail(4, "nft apply (backstop) failed");
        goto abort;
    }
    if (nft_verify(TABLE_BACKSTOP) != 0) {
        set_fail(4, "nft verify (backstop) failed");
        goto abort;
    }
    step_done(4, "backstop", "table inet %s guard: veth-scoped drops, policy accept",
              TABLE_BACKSTOP);

    /* step 5 — both rulesets re-verified; a queued rule counts as absent */
    if (nft_verify(TABLE_BACKSTOP) != 0) {
        set_fail(5, "backstop re-verify failed");
        goto abort;
    }
    if (sendb(p2c[1], 'R') != 0) {
        set_fail(5, "cannot request the child's re-verify");
        goto abort;
    }
    if (expect_status(c2p[0], '5', 5, "child re-verify") != 0)
        goto abort;
    step_done(5, "verify", "both rulesets present and active (nft -j list, non-empty)");

    /* step 6 — cgroup join, then the bpf attempt whose result is either
     * lab's recorded scope boundary or an abort */
    if (cgroup_setup() != 0)
        goto abort;
    if (bpf_probe_step() != 0)
        goto abort;
    if (sendb(p2c[1], 'S') != 0) {
        set_fail(6, "cannot release the child's drops");
        goto abort;
    }

    /* step 7 — drops complete inside the helper */
    if (expect_status(c2p[0], '7', 7, "capability drops") != 0)
        goto abort;
    step_done(7, "drops", "NNP, empty capset, dumpable 0, uid %u honored",
              (unsigned)g_rid);

    /* step 8 — the observer is probes/' scope; lab records the absence */
    if (lab) {
        step_done(8, "observer",
                  "not present — ringbuf and observer arrive with probes/ "
                  "(lab scope, §2.1)");
    } else {
        set_fail(8, "observer not implemented (loader lands with probes/)");
        goto abort;
    }

    /* step 9 — exec the target; this process stays to reap and tear down */
    if (sendb(p2c[1], '9') != 0) {
        set_fail(9, "cannot release the target");
        goto abort;
    }
    if (await_exec(c2p[0]) != 0)
        goto abort;
    close(p2c[1]);
    p2c[1] = -1;
    close(c2p[0]);
    c2p[0] = -1;
    step_done(9, "exec", "target running with protocol fds CLOEXEC");

    if (wait_target(&st) != 0) {
        set_fail(9, "interrupted while waiting for the target");
        goto abort;
    }
    g_cpid = -1;
    if (WIFEXITED(st)) {
        g_target_exit = WEXITSTATUS(st);
    } else if (WIFSIGNALED(st)) {
        g_target_exit = 128 + WTERMSIG(st);
    } else {
        set_fail(9, "target did not exit cleanly");
        goto abort;
    }
    teardown();
    emit_report("ok");
    return g_target_exit;

abort:
    if (p2c[1] >= 0)
        close(p2c[1]);
    if (c2p[0] >= 0)
        close(c2p[0]);
    reap_helper();
    teardown();
    emit_report("aborted");
    return EXIT_ABORT;
}
