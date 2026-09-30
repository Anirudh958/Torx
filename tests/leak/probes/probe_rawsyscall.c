/* probe_rawsyscall.c — adversarial probe: reach an IPv4 target while
 * bypassing libc's connect() entirely.
 *
 * LD_PRELOAD interposes on libc's dynamic symbol table. It cannot see a
 * direct syscall. This probe proves the difference empirically: the same
 * connection attempt, once through libc and once through syscall(2).
 *
 * Exit codes: identical to probe_connect.c.
 *   0  reached the target directly
 *   1  failed (errno printed)
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int main(int argc, char **argv)
{
    const char *ip   = (argc > 1) ? argv[1] : "1.1.1.1";
    int         port = (argc > 2) ? atoi(argv[2]) : 443;

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { fprintf(stderr, "socket: %s\n", strerror(errno)); return 3; }

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port   = htons((unsigned short)port);
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) return 4;

    long rc = syscall(__NR_connect, s, (struct sockaddr *)&a, sizeof a);
    if (rc == 0) {
        close(s);
        return 0;
    }
    fprintf(stderr, "syscall connect: %s\n", strerror(errno));
    close(s);
    return 1;
}
