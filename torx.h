/* torx.h — LD_PRELOAD Tor SOCKS4a shim (research artifact)
 *
 * Copyright (c) 2026 <your name>
 * SPDX-License-Identifier: MIT
 *
 * WARNING: This is a teaching/research artifact. It has known
 * limitations. See LIMITATIONS.md. Do not rely on it for anonymity
 * without reading that document.
 */
#ifndef TORX_H
#define TORX_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* ---- Configuration (env-overridable) ---- */
#define TORX_DEFAULT_PROXY   "127.0.0.1"
#define TORX_DEFAULT_PORT    9050
#define TORX_MAX_USERID      16   /* SOCKS4 userid field we send */

/* SOCKS4 protocol constants */
#define SOCKS4_VERSION   4
#define SOCKS4_CMD_CONNECT 1
#define SOCKS4_REP_OK    90
#define SOCKS4_REP_REJECT 91

/* SOCKS4a sentinel: DSTIP=0.0.0.1 means "hostname follows userid" */
#define SOCKS4A_INADDR  0x0100007fU  /* little-endian 0.0.0.1 */

/* Wire sizes (not struct-cast — we build explicitly) */
#define SOCKS4_REQ_FIXED   8   /* VN CD DSTPORT DSTIP */
#define SOCKS4_REP_SIZE    8

/* Public hook prototypes (must match libc exactly) */
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

#endif /* TORX_H */