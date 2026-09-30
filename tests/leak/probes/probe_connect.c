/* probe_connect.c — control probe: plain libc connect() to an IPv4 target.
 *
 * Used twice by the harness:
 *   - dynamically linked  : LD_PRELOAD applies, shim should intercept
 *   - statically  linked  : LD_PRELOAD is ignored, shim cannot intercept
 *
 * Exit codes:
 *   0  connection succeeded (reached the target directly)
 *   1  connection failed    (errno printed to stderr)
 *   3  socket() failed
 *   4  bad address argument
 *
 * Under TORX_PORT=1 the shim's intercept path fails by construction, so:
 *   exit 1  => the shim saw this connect()   (intercepted)
 *   exit 0  => the shim did NOT see it       (bypassed)
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
    int         port = (argc > 2) ? atoi(argv[2]) : 443;

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { fprintf(stderr, "socket: %s\n", strerror(errno)); return 3; }

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port   = htons((unsigned short)port);
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) return 4;

    if (connect(s, (struct sockaddr *)&a, sizeof a) == 0) {
        close(s);
        return 0;
    }
    fprintf(stderr, "connect: %s\n", strerror(errno));
    close(s);
    return 1;
}
