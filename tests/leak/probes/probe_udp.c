/* probe_udp.c — does the shim distinguish SOCK_STREAM from SOCK_DGRAM?
 *
 * A correct shim must not hijack a UDP connect(): SOCKS4 is TCP-only, so
 * the only sane behaviours are passthrough (documented: UDP is not
 * anonymized) or a clean error. dup2()-ing a Tor TCP socket over a
 * connected UDP socket silently converts the app's datagram socket into
 * a stream socket.
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

    close(s);
    if (rc == 0) return 0;
    fprintf(stderr, "connect: %s\n", strerror(saved));
    return 1;
}
