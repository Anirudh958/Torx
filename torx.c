/* TORX.c — LD_PRELOAD Tor SOCKS4a shim (research artifact)
 *
 * Copyright (c) 2026 <your name>
 * SPDX-License-Identifier: MIT
 *
 * Routes AF_INET TCP connect() calls through a local Tor SOCKS port.
 * Everything else (AF_INET6, AF_UNIX, loopback, non-TCP) is passed
 * through to the real connect(). See LIMITATIONS.md.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "torx.h"

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>        /* struct addrinfo */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>         /* time(2) */
#include <unistd.h>
#include <sys/types.h>
#include <sys/random.h>   /* getrandom(2) */

/* ------------------------------------------------------------------ */
/* Real libc symbols — resolved once at load time                     */
/* ------------------------------------------------------------------ */

/* dlsym(3) returns void *. ISO C forbids casting a void * to a function
 * pointer and then calling it; GCC's -Wcast-function-type also rejects
 * the cast because the types are incompatible. The memcpy idiom is the
 * POSIX-blessed workaround (POSIX explicitly allows dlsym's result to be
 * copied into a function pointer). */
#define RESOLVE_SYM(dst, name)                       \
    do {                                             \
        void *sym_ = dlsym(RTLD_NEXT, (name));       \
        memcpy(&(dst), &sym_, sizeof (dst));         \
    } while (0)

static int  (*real_connect)(int, const struct sockaddr *, socklen_t) = NULL;
static int  (*real_getaddrinfo)(const char *, const char *,
                                const struct addrinfo *,
                                struct addrinfo **) = NULL;

static pthread_once_t init_once = PTHREAD_ONCE_INIT;
static int            init_ok   = 0;

/* ---- Config (overridable via TORX_PROXY / TORX_PORT) ---- */
static const char *proxy_host = TORX_DEFAULT_PROXY;
static int         proxy_port = TORX_DEFAULT_PORT;

static void apply_config(void)
{
    const char *h = getenv("TORX_PROXY");
    const char *p = getenv("TORX_PORT");

    if (h && h[0] != '\0') proxy_host = h;
    if (p && p[0] != '\0') {
        char *end = NULL;
        long  v   = strtol(p, &end, 10);
        if (end && *end == '\0' && v > 0 && v <= 65535)
            proxy_port = (int)v;
    }
}

static void resolve_real_symbols(void)
{
    RESOLVE_SYM(real_connect, "connect");
    RESOLVE_SYM(real_getaddrinfo, "getaddrinfo");

    init_ok = (real_connect != NULL);   /* getaddrinfo hook is optional */
    apply_config();
}

__attribute__((constructor))
static void TORX_init(void)
{
    pthread_once(&init_once, resolve_real_symbols);
}

/* ------------------------------------------------------------------ */
/* Debug                                                              */
/* ------------------------------------------------------------------ */

static int debug_enabled(void)
{
    const char *v = getenv("TORX_DEBUG");
    return v && v[0] == '1';
}

/* Async-signal-safe-ish debug: one write(2), no stdio. */
static void dbg(const char *msg)
{
    if (!debug_enabled()) return;
    (void)!write(STDERR_FILENO, msg, strlen(msg));
}

/* ------------------------------------------------------------------ */
/* Small I/O helpers — handle partial reads/writes                    */
/* ------------------------------------------------------------------ */

static ssize_t write_all(int fd, const void *buf, size_t len)
{
    const unsigned char *p = buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, p + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) { errno = EPIPE; return -1; }
        off += (size_t)n;
    }
    return (ssize_t)off;
}

static ssize_t read_all(int fd, void *buf, size_t len)
{
    unsigned char *p = buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, p + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) { errno = ECONNRESET; return -1; }
        off += (size_t)n;
    }
    return (ssize_t)off;
}

/* ------------------------------------------------------------------ */
/* Per-process SOCKS4 userid — enables Tor IsolateSOCKSAuth            */
/* ------------------------------------------------------------------ */

static void make_userid(char out[TORX_MAX_USERID + 1])
{
    uint32_t r = 0;
    if (getrandom(&r, sizeof r, 0) != (ssize_t)sizeof r) {
        r = (uint32_t)getpid() ^ (uint32_t)time(NULL);
    }
    /* "tz-" + 8 hex chars + NUL = 12 bytes, safe. */
    snprintf(out, TORX_MAX_USERID + 1, "tz-%08x", r);
}

/* ------------------------------------------------------------------ */
/* SOCKS4a request builder — explicit wire format, no struct casts    */
/* ------------------------------------------------------------------ */

struct socks4_req {
    unsigned char buf[SOCKS4_REQ_FIXED + TORX_MAX_USERID + 1 + 256];
    size_t        len;
};

static int build_socks4a_request(struct socks4_req *r,
                                 uint32_t dst_ip_be,
                                 uint16_t dst_port_be,
                                 const char *hostname /* may be NULL */)
{
    char userid[TORX_MAX_USERID + 1];
    make_userid(userid);
    size_t ulen = strlen(userid);
    size_t hlen = hostname ? strlen(hostname) : 0;

    if (ulen > 255) return -1;
    if (hlen > 255) { errno = ENAMETOOLONG; return -1; }

    size_t off = 0;
    r->buf[off++] = SOCKS4_VERSION;
    r->buf[off++] = SOCKS4_CMD_CONNECT;
    /* DSTPORT is big-endian on the wire */
    r->buf[off++] = (unsigned char)((dst_port_be >> 8) & 0xff);
    r->buf[off++] = (unsigned char)( dst_port_be       & 0xff);

    if (hostname) {
        /* SOCKS4a: DSTIP = 0.0.0.1, hostname follows userid + NUL */
        r->buf[off++] = 0x00;
        r->buf[off++] = 0x00;
        r->buf[off++] = 0x00;
        r->buf[off++] = 0x01;
    } else {
        /* SOCKS4: DSTIP as-is (network byte order already) */
        memcpy(r->buf + off, &dst_ip_be, 4);
        off += 4;
    }

    memcpy(r->buf + off, userid, ulen); off += ulen;
    r->buf[off++] = 0x00;                       /* userid terminator */
    if (hostname) {
        memcpy(r->buf + off, hostname, hlen); off += hlen;
        r->buf[off++] = 0x00;                   /* hostname terminator */
    }

    r->len = off;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Tor SOCKS dial                                                     */
/* ------------------------------------------------------------------ */

static int dial_tor(void)
{
    int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) return -1;

    struct sockaddr_in tor;
    memset(&tor, 0, sizeof tor);
    tor.sin_family = AF_INET;
    tor.sin_port   = htons((uint16_t)proxy_port);

    if (inet_pton(AF_INET, proxy_host, &tor.sin_addr) != 1) {
        close(s);
        errno = EINVAL;
        return -1;
    }

    if (real_connect(s, (struct sockaddr *)&tor, sizeof tor) < 0) {
        int e = errno;
        close(s);
        errno = e;
        return -1;
    }
    return s;
}

/* Returns 0 on success, -1 on failure (errno set). */
static int socks4_handshake(int s, const struct sockaddr_in *dst,
                            const char *hostname)
{
    struct socks4_req req;
    if (build_socks4a_request(&req,
                              dst->sin_addr.s_addr,      /* be */
                              ntohs(dst->sin_port),      /* host order; we re-emit be */
                              hostname) < 0)
        return -1;

    if (write_all(s, req.buf, req.len) < 0)
        return -1;

    unsigned char rep[SOCKS4_REP_SIZE];
    if (read_all(s, rep, sizeof rep) < 0)
        return -1;

    if (rep[0] != 0x00) {            /* VN in reply is 0 */
        errno = EPROTO;
        return -1;
    }
    if (rep[1] != SOCKS4_REP_OK) {
        errno = ECONNREFUSED;
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* The hook                                                           */
/* ------------------------------------------------------------------ */

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    pthread_once(&init_once, resolve_real_symbols);
    if (!init_ok) {
        errno = ENOSYS;
        return -1;
    }

    /* --- Passthrough conditions --------------------------------- */
    if (addr == NULL || addrlen < sizeof(struct sockaddr)) {
        return real_connect(sockfd, addr, addrlen);
    }
    if (addr->sa_family != AF_INET) {
        /* AF_INET6, AF_UNIX, AF_NETLINK, ... — not our problem. */
        return real_connect(sockfd, addr, addrlen);
    }
    if (addrlen < sizeof(struct sockaddr_in)) {
        return real_connect(sockfd, addr, addrlen);
    }

    const struct sockaddr_in *dst = (const struct sockaddr_in *)addr;

    /* Loopback → never route through Tor. */
    uint32_t ip = ntohl(dst->sin_addr.s_addr);
    if ((ip >> 24) == 127) {
        return real_connect(sockfd, addr, addrlen);
    }

    /* Private / link-local / multicast / broadcast → passthrough.
     * Tor can't reach these anyway, and hijacking them breaks LAN apps. */
    if ((ip >> 24) == 10) return real_connect(sockfd, addr, addrlen);
    if ((ip >> 20) == 0xAC1) return real_connect(sockfd, addr, addrlen); /* 172.16/12 */
    if ((ip >> 16) == 0xC0A8) return real_connect(sockfd, addr, addrlen); /* 192.168/16 */
    if ((ip >> 16) == 0xA9FE) return real_connect(sockfd, addr, addrlen); /* 169.254/16 */
    if ((ip >> 28) == 0xE) return real_connect(sockfd, addr, addrlen);    /* 224/4 */
    if (ip == 0xFFFFFFFFU) return real_connect(sockfd, addr, addrlen);

    /* --- Route through Tor -------------------------------------- */
    dbg("[TORX] routing connect() through Tor\n");

    int tor = dial_tor();
    if (tor < 0) return -1;

    if (socks4_handshake(tor, dst, /*hostname=*/NULL) < 0) {
        int e = errno;
        close(tor);
        errno = e;
        return -1;
    }

    /* Replace the app's fd with the Tor-connected socket. */
    if (dup2(tor, sockfd) < 0) {
        int e = errno;
        close(tor);
        errno = e;
        return -1;
    }
    close(tor);   /* sockfd now owns the connection */

    /* Preserve blocking-ness of the original? We can't easily know,
     * but SOCK_CLOEXEC on the new fd is fine; the app's fd table
     * entry is now our socket. Documented limitation. */
    return 0;
}