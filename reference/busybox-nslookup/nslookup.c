#include <resolv.h>
// #include <arpa/inet.h>
// #include <netdb.h>
#include "libbb.h"
// #include "common_bufsiz.h"

static int print_host(const char *hostname, const char *header) {
    /* We can't use xhost2sockaddr() - we want to get ALL addresses,
	 * not just one */
    struct addrinfo *result = NULL;
    int rc;
    struct addrinfo hint;

    memset(&hint, 0, sizeof(hint));
    /* hint.ai_family = AF_UNSPEC; - zero anyway */
    /* Needed. Or else we will get each address thrice (or more)
	 * for each possible socket type (tcp,udp,raw...): */
    hint.ai_socktype = SOCK_STREAM;
    // hint.ai_flags = AI_CANONNAME;
    rc = getaddrinfo(hostname, NULL /*service*/, &hint, &result);

    if (rc == 0) {
        struct addrinfo *cur = result;
        unsigned cnt = 0;

        printf("%-10s %s\n", header, hostname);
        // puts(cur->ai_canonname); ?
        while (cur) {
            char *dotted, *revhost;
            dotted = xmalloc_sockaddr2dotted_noport(cur->ai_addr);
            revhost = xmalloc_sockaddr2hostonly_noport(cur->ai_addr);

            printf("Address %u: %s%c", ++cnt, dotted, revhost ? ' ' : '\n');
            if (revhost) {
                puts(revhost);
                if (ENABLE_FEATURE_CLEAN_UP)
                    free(revhost);
            }
            if (ENABLE_FEATURE_CLEAN_UP)
                free(dotted);
            cur = cur->ai_next;
        }
    } else {
#if ENABLE_VERBOSE_RESOLUTION_ERRORS
        bb_error_msg("can't resolve '%s': %s", hostname, gai_strerror(rc));
#else
        bb_error_msg("can't resolve '%s'", hostname);
#endif
    }
    if (ENABLE_FEATURE_CLEAN_UP && result)
        freeaddrinfo(result);
    return (rc != 0);
}

/* lookup the default nameserver and display it */
static void server_print(void) {
    char *server;
    struct sockaddr *sa;

#if ENABLE_FEATURE_IPV6
    sa = (struct sockaddr *)_res._u._ext.nsaddrs[0];
    if (!sa)
#endif
        sa = (struct sockaddr *)&_res.nsaddr_list[0];
    server = xmalloc_sockaddr2dotted_noport(sa);

    print_host(server, "Server:");
    if (ENABLE_FEATURE_CLEAN_UP)
        free(server);
    bb_putchar('\n');
}

/* alter the global _res nameserver structure to use
   an explicit dns server instead of what is in /etc/resolv.conf */
static void set_default_dns(const char *server) {
    len_and_sockaddr *lsa;

    if (!server)
        return;

    /* NB: this works even with, say, "[::1]:5353"! :) */
    lsa = xhost2sockaddr(server, 53);

    if (lsa->u.sa.sa_family == AF_INET) {
        _res.nscount = 1;
        /* struct copy */
        _res.nsaddr_list[0] = lsa->u.sin;
    }
#if ENABLE_FEATURE_IPV6
    /* Hoped libc can cope with IPv4 address there too.
	 * No such luck, glibc 2.4 segfaults even with IPv6,
	 * maybe I misunderstand how to make glibc use IPv6 addr?
	 * (uclibc 0.9.31+ should work) */
    if (lsa->u.sa.sa_family == AF_INET6) {
        // glibc neither SEGVs nor sends any dgrams with this
        // (strace shows no socket ops):
        //_res.nscount = 0;
        _res._u._ext.nscount = 1;
        /* store a pointer to part of malloc'ed lsa */
        _res._u._ext.nsaddrs[0] = &lsa->u.sin6;
        /* must not free(lsa)! */
    }
#endif
}

int nslookup_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int nslookup_main(int argc, char **argv) {
    /* We allow 1 or 2 arguments.
	 * The first is the name to be looked up and the second is an
	 * optional DNS server with which to do the lookup.
	 * More than 3 arguments is an error to follow the pattern of the
	 * standard nslookup */
    if (!argv[1] || argv[1][0] == '-' || argc > 3)
        bb_show_usage();

    /* initialize DNS structure _res used in printing the default
	 * name server and in the explicit name server option feature. */
    res_init();
    /* rfc2133 says this enables IPv6 lookups */
    /* (but it also says "may be enabled in /etc/resolv.conf") */
    /*_res.options |= RES_USE_INET6;*/

    set_default_dns(argv[2]);

    server_print();

    /* getaddrinfo and friends are free to request a resolver
	 * reinitialization. Just in case, set_default_dns() again
	 * after getaddrinfo (in server_print). This reportedly helps
	 * with bug 675 "nslookup does not properly use second argument"
	 * at least on Debian Wheezy and Openwrt AA (eglibc based).
	 */
    set_default_dns(argv[2]);

    return print_host(argv[1], "Name:");
}
