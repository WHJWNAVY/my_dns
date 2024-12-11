/* vi: set sw=4 ts=4: */
/*
 * Utility routines.
 *
 * Connect to host at port using address resolution from getaddrinfo
 *
 * Licensed under GPLv2, see file LICENSE in this source tree.
 */

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/socket.h> /* netinet/in.h needs it */
#include <netinet/in.h>
#include <net/if.h>
#include <sys/un.h>

#include "libbb.h"

// Die if we can't allocate and zero size bytes of memory.
void *FAST_FUNC xzalloc(size_t size) {
    void *ptr = xmalloc(size);
    memset(ptr, 0, size);
    return ptr;
}

void FAST_FUNC set_nport(struct sockaddr *sa, unsigned port) {
#if ENABLE_FEATURE_IPV6
    if (sa->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (void *)sa;
        sin6->sin6_port = port;
        return;
    }
#endif
    if (sa->sa_family == AF_INET) {
        struct sockaddr_in *sin = (void *)sa;
        sin->sin_port = port;
        return;
    }
    /* What? UNIX socket? IPX?? :) */
}

char *FAST_FUNC is_prefixed_with(const char *string, const char *key) {
#if 0 /* Two passes over key - probably slower */
        int len = strlen(key);
        if (strncmp(string, key, len) == 0)
                return string + len;
        return NULL;
#else /* Open-coded */
    while (*key != '\0') {
        if (*key != *string)
            return NULL;
        key++;
        string++;
    }
    return (char *)string;
#endif
}

/* We hijack this constant to mean something else */
/* It doesn't hurt because we will remove this bit anyway */
#define DIE_ON_ERROR AI_CANONNAME
/* host: "1.2.3.4[:port]", "www.google.com[:port]"
 * port: if neither of above specifies port # */
static len_and_sockaddr *str2sockaddr(const char *host, int port, IF_FEATURE_IPV6(sa_family_t af, ) int ai_flags) {
    IF_NOT_FEATURE_IPV6(sa_family_t af = AF_INET;)
    int rc;
    len_and_sockaddr *r;
    struct addrinfo *result = NULL;
    struct addrinfo *used_res;
    const char *org_host = host; /* only for error msg */
    const char *cp;
    struct addrinfo hint;

    if (ENABLE_FEATURE_UNIX_LOCAL && is_prefixed_with(host, "local:")) {
        struct sockaddr_un *sun;

        r = xzalloc(LSA_LEN_SIZE + sizeof(struct sockaddr_un));
        r->len = sizeof(struct sockaddr_un);
        r->u.sa.sa_family = AF_UNIX;
        sun = (struct sockaddr_un *)&r->u.sa;
        safe_strncpy(sun->sun_path, host + 6, sizeof(sun->sun_path));
        return r;
    }

    r = NULL;

    /* Ugly parsing of host:addr */
    if (ENABLE_FEATURE_IPV6 && host[0] == '[') {
        /* Even uglier parsing of [xx]:nn */
        host++;
        cp = strchr(host, ']');
        if (!cp || (cp[1] != ':' && cp[1] != '\0')) {
            /* Malformed: must be [xx]:nn or [xx] */
            bb_error_msg("bad address '%s'", org_host);
            if (ai_flags & DIE_ON_ERROR)
                xfunc_die();
            return NULL;
        }
    } else {
        cp = strrchr(host, ':');
        if (ENABLE_FEATURE_IPV6 && cp && strchr(host, ':') != cp) {
            /* There is more than one ':' (e.g. "::1") */
            cp = NULL; /* it's not a port spec */
        }
    }
    if (cp) { /* points to ":" or "]:" */
        int sz = cp - host + 1;

        host = safe_strncpy(alloca(sz), host, sz);
        if (ENABLE_FEATURE_IPV6 && *cp != ':') {
            cp++;            /* skip ']' */
            if (*cp == '\0') /* [xx] without port */
                goto skip;
        }
        cp++; /* skip ':' */
        port = bb_strtou(cp, NULL, 10);
        if (errno || (unsigned)port > 0xffff) {
            bb_error_msg("bad port spec '%s'", org_host);
            if (ai_flags & DIE_ON_ERROR)
                xfunc_die();
            return NULL;
        }
    skip:;
    }

    /* Next two if blocks allow to skip getaddrinfo()
	 * in case host name is a numeric IP(v6) address.
	 * getaddrinfo() initializes DNS resolution machinery,
	 * scans network config and such - tens of syscalls.
	 */
    /* If we were not asked specifically for IPv6,
	 * check whether this is a numeric IPv4 */
    IF_FEATURE_IPV6(if (af != AF_INET6)) {
        struct in_addr in4;
        if (inet_aton(host, &in4) != 0) {
            r = xzalloc(LSA_LEN_SIZE + sizeof(struct sockaddr_in));
            r->len = sizeof(struct sockaddr_in);
            r->u.sa.sa_family = AF_INET;
            r->u.sin.sin_addr = in4;
            goto set_port;
        }
    }
#if ENABLE_FEATURE_IPV6
    /* If we were not asked specifically for IPv4,
	 * check whether this is a numeric IPv6 */
    if (af != AF_INET) {
        struct in6_addr in6;
        if (inet_pton(AF_INET6, host, &in6) > 0) {
            r = xzalloc(LSA_LEN_SIZE + sizeof(struct sockaddr_in6));
            r->len = sizeof(struct sockaddr_in6);
            r->u.sa.sa_family = AF_INET6;
            r->u.sin6.sin6_addr = in6;
            goto set_port;
        }
    }
#endif

    memset(&hint, 0, sizeof(hint));
    hint.ai_family = af;
    /* Need SOCK_STREAM, or else we get each address thrice (or more)
	 * for each possible socket type (tcp,udp,raw...): */
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_flags = ai_flags & ~DIE_ON_ERROR;
    rc = getaddrinfo(host, NULL, &hint, &result);
    if (rc || !result) {
        bb_error_msg("bad address '%s'", org_host);
        if (ai_flags & DIE_ON_ERROR)
            xfunc_die();
        goto ret;
    }
    used_res = result;
#if ENABLE_FEATURE_PREFER_IPV4_ADDRESS
    while (1) {
        if (used_res->ai_family == AF_INET)
            break;
        used_res = used_res->ai_next;
        if (!used_res) {
            used_res = result;
            break;
        }
    }
#endif
    r = xmalloc(LSA_LEN_SIZE + used_res->ai_addrlen);
    r->len = used_res->ai_addrlen;
    memcpy(&r->u.sa, used_res->ai_addr, used_res->ai_addrlen);

set_port:
    set_nport(&r->u.sa, htons(port));
ret:
    if (result)
        freeaddrinfo(result);
    return r;
}
#if !ENABLE_FEATURE_IPV6
#define str2sockaddr(host, port, af, ai_flags) str2sockaddr(host, port, ai_flags)
#endif

len_and_sockaddr *FAST_FUNC xhost2sockaddr(const char *host, int port) {
    return str2sockaddr(host, port, AF_UNSPEC, DIE_ON_ERROR);
}

// Die with an error message if we can't malloc() enough space and do an
// sprintf() into that space.
char *FAST_FUNC xasprintf(const char *format, ...) {
    va_list p;
    int r;
    char *string_ptr;

    va_start(p, format);
    r = vasprintf(&string_ptr, format, p);
    va_end(p);

    if (r < 0)
        return NULL;
    return string_ptr;
}

/* We hijack this constant to mean something else */
/* It doesn't hurt because we will add this bit anyway */
#define IGNORE_PORT NI_NUMERICSERV
static char *FAST_FUNC sockaddr2str(const struct sockaddr *sa, int flags) {
    char host[128];
    char serv[16];
    int rc;
    socklen_t salen;

    if (ENABLE_FEATURE_UNIX_LOCAL && sa->sa_family == AF_UNIX) {
        struct sockaddr_un *sun = (struct sockaddr_un *)sa;
        return xasprintf("local:%.*s", (int)sizeof(sun->sun_path), sun->sun_path);
    }

    salen = LSA_SIZEOF_SA;
#if ENABLE_FEATURE_IPV6
    if (sa->sa_family == AF_INET)
        salen = sizeof(struct sockaddr_in);
    if (sa->sa_family == AF_INET6)
        salen = sizeof(struct sockaddr_in6);
#endif
    rc = getnameinfo(sa, salen, host, sizeof(host),
                     /* can do ((flags & IGNORE_PORT) ? NULL : serv) but why bother? */
                     serv, sizeof(serv),
                     /* do not resolve port# into service _name_ */
                     flags | NI_NUMERICSERV);
    if (rc)
        return NULL;
    if (flags & IGNORE_PORT)
        return xstrdup(host);
#if ENABLE_FEATURE_IPV6
    if (sa->sa_family == AF_INET6) {
        if (strchr(host, ':')) /* heh, it's not a resolved hostname */
            return xasprintf("[%s]:%s", host, serv);
        /*return xasprintf("%s:%s", host, serv);*/
        /* - fall through instead */
    }
#endif
    /* For now we don't support anything else, so it has to be INET */
    /*if (sa->sa_family == AF_INET)*/
    return xasprintf("%s:%s", host, serv);
    /*return xstrdup(host);*/
}

char *FAST_FUNC xmalloc_sockaddr2host_noport(const struct sockaddr *sa) {
    return sockaddr2str(sa, IGNORE_PORT);
}

char *FAST_FUNC xmalloc_sockaddr2hostonly_noport(const struct sockaddr *sa) {
    return sockaddr2str(sa, NI_NAMEREQD | IGNORE_PORT);
}
#ifndef NI_NUMERICSCOPE
#define NI_NUMERICSCOPE 0
#endif
char *FAST_FUNC xmalloc_sockaddr2dotted_noport(const struct sockaddr *sa) {
    return sockaddr2str(sa, NI_NUMERICHOST | NI_NUMERICSCOPE | IGNORE_PORT);
}
