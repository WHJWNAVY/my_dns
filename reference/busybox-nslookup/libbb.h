#ifndef _LIBBB_H_
#define _LIBBB_H_

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stddef.h>
#include <stdarg.h>

#include <errno.h>
#include <time.h>
#include <poll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#define FAST_FUNC
#define RETURNS_MALLOC
#define ENABLE_LONG_OPTS 1
#define ENABLE_FEATURE_IPV6 1
#define IF_FEATURE_IPV6(...) __VA_ARGS__
#define IF_NOT_FEATURE_IPV6(...)
#define ENABLE_FEATURE_CLEAN_UP 1
#define ENABLE_FEATURE_UNIX_LOCAL 0
#define ENABLE_FEATURE_PREFER_IPV4_ADDRESS 0
#define MAIN_EXTERNALLY_VISIBLE

#if defined(i386) || defined(__x86_64__) || defined(__mips__) || defined(__cris__)
/* add other arches which benefit from this... */
typedef signed char smallint;
typedef unsigned char smalluint;
#else
/* for arches where byte accesses generate larger code: */
typedef int smallint;
typedef unsigned smalluint;
#endif

typedef struct llist_t {
    struct llist_t *link;
    char *data;
} llist_t;

typedef struct len_and_sockaddr {
    socklen_t len;
    union {
        struct sockaddr sa;
        struct sockaddr_in sin;
#if ENABLE_FEATURE_IPV6
        struct sockaddr_in6 sin6;
#endif
    } u;
} len_and_sockaddr;
enum {
    LSA_LEN_SIZE = offsetof(len_and_sockaddr, u),
    LSA_SIZEOF_SA = sizeof(union {
        struct sockaddr sa;
        struct sockaddr_in sin;
#if ENABLE_FEATURE_IPV6
        struct sockaddr_in6 sin6;
#endif
    })
};

len_and_sockaddr *FAST_FUNC xhost2sockaddr(const char *host, int port);
/* This one doesn't append :PORTNUM */
char *xmalloc_sockaddr2host_noport(const struct sockaddr *sa) FAST_FUNC RETURNS_MALLOC;
/* This one also doesn't fall back to dotted IP (returns NULL) */
char *xmalloc_sockaddr2hostonly_noport(const struct sockaddr *sa) FAST_FUNC RETURNS_MALLOC;
char *xmalloc_sockaddr2dotted_noport(const struct sockaddr *sa) FAST_FUNC RETURNS_MALLOC;

#define bb_putchar putchar
#define xstrdup strdup
#define xmalloc malloc
#define safe_strncpy strncpy
#define bb_strtou strtoul
#define xfunc_die() do{;}while(0)
#define bb_error_msg(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#define bb_show_usage() fprintf(stderr, "Usage: nslookup HOST [DNS_SERVER]\n\nQuery DNS about HOST\n")

#define nslookup_main main
#endif