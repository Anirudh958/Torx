/* probe_udp.c — does the shim distinguish SOCK_STREAM from SOCK_DGRAM?
 *
 * A correct shim must not hijack a UDP connect(): SOCKS4 is TCP-only, so
 * the only sane behaviours are passthrough (documented: UDP is not
 * anonymized) or a clean error. dup2()-ing a Tor TCP socket over a
 * connected UDP socket silently converts the app's datagram socket into
 * a stream socket.
 *
 * Beyond detecting the swap (so_type), the probe measures what the app
 * then OBSERVES — because a corruption that raises no errno is invisible
 * to everything except getsockopt(SO_TYPE):
 *   send()        on the swapped fd
 *   sendto()      with a DIFFERENT destination address
 *   connect()     a second time (does the shim re-route the now-TCP fd?)
 *
 * Output is machine-parseable (key: rc=N errno=N) for run.sh evidence.
 *
 * Exit codes:
 *   0  connect succeeded
 *   1  connect failed (errno printed)
 *   3  socket() failed
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static void show(const char *what, ssize_t rc)
{
    int e = errno;
    fprintf(stderr, "%s: rc=%zd errno=%d\n", what, rc, rc < 0 ? e : 0);
}

int main(int argc, char **argv)
{
    const char *ip   = (argc > 1) ? argv[1] : "1.1.1.1";
    int         port = (argc > 2) ? atoi(argv[2]) : 53;

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { fprintf(stderr, "socket: %s\n", strerror(errno)); return 3; }

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port   = htons((unsigned short)port);
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) return 4;

    int rc = connect(s, (struct sockaddr *)&a, sizeof a);
    int saved = errno;

    /* Did the fd's socket type change underneath us? SOCK_DGRAM==2,
     * SOCK_STREAM==1. A dup2() swap makes the UDP fd a TCP socket. */
    int typ = -1; socklen_t tl = sizeof typ;
    if (getsockopt(s, SOL_SOCKET, SO_TYPE, &typ, &tl) == 0)
        fprintf(stderr, "so_type=%d\n", typ);

    if (rc == 0) {
        /* connect "succeeded": either swapped (live Tor) or untouched
         * (no shim). Measure what the application can detect. */
        errno = 0;
        show("send", send(s, "x", 1, MSG_NOSIGNAL));

        struct sockaddr_in b;
        memset(&b, 0, sizeof b);
        b.sin_family = AF_INET;
        b.sin_port   = htons(53);
        if (inet_pton(AF_INET, "8.8.8.8", &b.sin_addr) != 1)
            memset(&b, 0, sizeof b), b.sin_family = AF_INET;
        errno = 0;
        show("sendto", sendto(s, "y", 1, MSG_NOSIGNAL,
                              (struct sockaddr *)&b, sizeof b));

        errno = 0;
        show("reconnect", connect(s, (struct sockaddr *)&b, sizeof b));

        typ = -1; tl = sizeof typ;
        if (getsockopt(s, SOL_SOCKET, SO_TYPE, &typ, &tl) == 0)
            fprintf(stderr, "so_type_after=%d\n", typ);
    }

    close(s);
    if (rc == 0) return 0;
    fprintf(stderr, "connect: %s\n", strerror(saved));
    return 1;
}
