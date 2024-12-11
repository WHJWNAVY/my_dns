#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS 1
#endif

#include <stdio.h>

#include <errno.h>
#include <signal.h>

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#define sleep(x) Sleep(x * 1000)
#else
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/time.h>
#endif

#include "my_dns.h"

static char addrbuffer[64];
static char entrybuffer[256];
static char namebuffer[256];
static char sendbuffer[1024];
static mdns_record_txt_t txtbuffer[128];

static struct sockaddr_in service_address_ipv4;
static struct sockaddr_in6 service_address_ipv6;

static int has_ipv4;
static int has_ipv6;

static void *ipv4_address_from_string(struct sockaddr_in *addr, const char *src) {
    int ret = inet_pton(AF_INET, src, &(addr->sin_addr));
    return ((ret > 0) ? addr : NULL);
}

static void *ipv6_address_from_string(struct sockaddr_in6 *addr, const char *src) {
    int ret = inet_pton(AF_INET6, src, &(addr->sin6_addr));
    return ((ret > 0) ? addr : NULL);
}

static void *ip_address_from_string(void *addr, const char *src) {
    void *ret = ipv4_address_from_string(addr, src);
    if (ret == NULL) {
        ret = ipv6_address_from_string(addr, src);
    }

    return ret;
}

static mdns_string_t ipv4_address_to_string(char *buffer, size_t capacity, const struct sockaddr_in *addr,
                                            size_t addrlen) {

    char host[NI_MAXHOST] = {0};
    char service[NI_MAXSERV] = {0};
    mdns_string_t str = {0};
    int ret = 0, len = 0;
#if 0
    ret = getnameinfo((const struct sockaddr *)addr, (socklen_t)addrlen, host, NI_MAXHOST, service, NI_MAXSERV,
                      NI_NUMERICSERV | NI_NUMERICHOST);
    if (ret == 0) {
        if (addr->sin_port != 0) {
            len = snprintf(buffer, capacity, "%s:%s", host, service);
        } else {
            len = snprintf(buffer, capacity, "%s", host);
        }
    }
    if (len >= (int)capacity) {
        len = (int)capacity - 1;
    }
#else
    if (inet_ntop(addr->sin_family, &(addr->sin_addr), host, NI_MAXHOST) != NULL) {
        if (addr->sin_port != 0) {
            len = snprintf(buffer, capacity, "%s:%u", host, addr->sin_port);
        } else {
            len = snprintf(buffer, capacity, "%s", host);
        }
    }

    if (len >= (int)capacity) {
        len = (int)capacity - 1;
    }
#endif
    str.str = buffer;
    str.length = len;
    return str;
}

static mdns_string_t ipv6_address_to_string(char *buffer, size_t capacity, const struct sockaddr_in6 *addr,
                                            size_t addrlen) {
    char host[NI_MAXHOST] = {0};
    char service[NI_MAXSERV] = {0};
    mdns_string_t str = {0};
    int ret = 0, len = 0;
#if 0
    ret = getnameinfo((const struct sockaddr *)addr, (socklen_t)addrlen, host, NI_MAXHOST, service, NI_MAXSERV,
                      NI_NUMERICSERV | NI_NUMERICHOST);
    if (ret == 0) {
        if (addr->sin6_port != 0) {
            len = snprintf(buffer, capacity, "[%s]:%s", host, service);
        } else {
            len = snprintf(buffer, capacity, "%s", host);
        }
    }
    if (len >= (int)capacity) {
        len = (int)capacity - 1;
    }
#else
    if (inet_ntop(addr->sin6_family, &(addr->sin6_addr), host, NI_MAXHOST) != NULL) {
        if (addr->sin6_port != 0) {
            len = snprintf(buffer, capacity, "%s:%u", host, addr->sin6_port);
        } else {
            len = snprintf(buffer, capacity, "%s", host);
        }
    }

    if (len >= (int)capacity) {
        len = (int)capacity - 1;
    }
#endif
    str.str = buffer;
    str.length = len;
    return str;
}

static mdns_string_t ip_address_to_string(char *buffer, size_t capacity, const struct sockaddr *addr, size_t addrlen) {
    if (addr->sa_family == AF_INET6) {
        return ipv6_address_to_string(buffer, capacity, (const struct sockaddr_in6 *)addr, addrlen);
    }
    return ipv4_address_to_string(buffer, capacity, (const struct sockaddr_in *)addr, addrlen);
}

// Callback handling parsing answers to queries sent
static int mdns_query_callback(int sock, const struct sockaddr *from, size_t addrlen, mdns_entry_type_t entry,
                               uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data,
                               size_t size, size_t name_offset, size_t name_length, size_t record_offset,
                               size_t record_length, void *user_data) {
    size_t parsed = 0;
    size_t itxt = 0;
    struct sockaddr_in addr = {0};
    struct sockaddr_in6 addr6 = {0};
    mdns_string_t fromaddrstr = {0};
    mdns_string_t entrystr = {0};
    mdns_string_t namestr = {0};
    mdns_string_t addrstr = {0};
    mdns_record_srv_t srv = {0};

    (void)sizeof(sock);
    (void)sizeof(query_id);
    (void)sizeof(name_length);
    (void)sizeof(user_data);

    fromaddrstr = ip_address_to_string(addrbuffer, sizeof(addrbuffer), from, addrlen);
    const char *entrytype = (entry == MDNS_ENTRYTYPE_ANSWER)
                                ? "answer"
                                : ((entry == MDNS_ENTRYTYPE_AUTHORITY) ? "authority" : "additional");

    entrystr = mdns_string_extract(data, size, &name_offset, entrybuffer, sizeof(entrybuffer));
    if (rtype == MDNS_RECORDTYPE_PTR) {
        namestr = mdns_record_parse_ptr(data, size, record_offset, record_length, namebuffer, sizeof(namebuffer));
        printf("%.*s : %s %.*s PTR %.*s rclass 0x%x ttl %u length %d\n", MDNS_STRING_FORMAT(fromaddrstr), entrytype,
               MDNS_STRING_FORMAT(entrystr), MDNS_STRING_FORMAT(namestr), rclass, ttl, (int)record_length);
    } else if (rtype == MDNS_RECORDTYPE_SRV) {
        srv = mdns_record_parse_srv(data, size, record_offset, record_length, namebuffer, sizeof(namebuffer));
        printf("%.*s : %s %.*s SRV %.*s priority %d weight %d port %d\n", MDNS_STRING_FORMAT(fromaddrstr), entrytype,
               MDNS_STRING_FORMAT(entrystr), MDNS_STRING_FORMAT(srv.name), srv.priority, srv.weight, srv.port);
    } else if (rtype == MDNS_RECORDTYPE_A) {
        mdns_record_parse_a(data, size, record_offset, record_length, &addr);
        addrstr = ipv4_address_to_string(namebuffer, sizeof(namebuffer), &addr, sizeof(addr));
        printf("%.*s : %s %.*s A %.*s\n", MDNS_STRING_FORMAT(fromaddrstr), entrytype, MDNS_STRING_FORMAT(entrystr),
               MDNS_STRING_FORMAT(addrstr));
    } else if (rtype == MDNS_RECORDTYPE_AAAA) {
        mdns_record_parse_aaaa(data, size, record_offset, record_length, &addr6);
        addrstr = ipv6_address_to_string(namebuffer, sizeof(namebuffer), &addr6, sizeof(addr6));
        printf("%.*s : %s %.*s AAAA %.*s\n", MDNS_STRING_FORMAT(fromaddrstr), entrytype, MDNS_STRING_FORMAT(entrystr),
               MDNS_STRING_FORMAT(addrstr));
    } else if (rtype == MDNS_RECORDTYPE_TXT) {
        parsed = mdns_record_parse_txt(data, size, record_offset, record_length, txtbuffer,
                                       sizeof(txtbuffer) / sizeof(mdns_record_txt_t));
        for (itxt = 0; itxt < parsed; ++itxt) {
            if (txtbuffer[itxt].value.length) {
                printf("%.*s : %s %.*s TXT %.*s = %.*s\n", MDNS_STRING_FORMAT(fromaddrstr), entrytype,
                       MDNS_STRING_FORMAT(entrystr), MDNS_STRING_FORMAT(txtbuffer[itxt].key),
                       MDNS_STRING_FORMAT(txtbuffer[itxt].value));
            } else {
                printf("%.*s : %s %.*s TXT %.*s\n", MDNS_STRING_FORMAT(fromaddrstr), entrytype,
                       MDNS_STRING_FORMAT(entrystr), MDNS_STRING_FORMAT(txtbuffer[itxt].key));
            }
        }
    } else {
        printf("%.*s : %s %.*s type %u rclass 0x%x ttl %u length %d\n", MDNS_STRING_FORMAT(fromaddrstr), entrytype,
               MDNS_STRING_FORMAT(entrystr), rtype, rclass, ttl, (int)record_length);
    }
    return 0;
}

typedef struct {
    struct sockaddr_storage saddr;
    size_t addrlen;
} sockaddr_st;

static int load_dns_servers_from_string(sockaddr_st *addr, int port, const char *src) {
    struct sockaddr_in *in = NULL;
    struct sockaddr_in6 *in6 = NULL;
    size_t *slen = NULL;

    if ((addr == NULL) || (src == NULL)) {
        return -1;
    }

    in = (struct sockaddr_in *)&(addr->saddr);
    in6 = (struct sockaddr_in6 *)&(addr->saddr);
    slen = &(addr->addrlen);

    if (ipv4_address_from_string(in, src) != NULL) {
        in->sin_family = AF_INET;
        in->sin_port = htons((unsigned short)port);
        *slen = sizeof(struct sockaddr_in);
        MY_DEBUG("Load dns server: %s", src);
        return 0;
    } else if (ipv6_address_from_string(in6, src) != NULL) {
        in6->sin6_family = AF_INET6;
        in6->sin6_port = htons((unsigned short)port);
        *slen = sizeof(struct sockaddr_in6);
        MY_DEBUG("Load dns6 server: %s", src);
        return 0;
    } else {
        MY_ERROR("Invalid dns server: %s", src);
        return -1;
    }
}

#if 0
/* The function obtains the DNS servers stored in /etc/resolv.conf */
static int load_dns_servers(sockaddr_st *addrs, int max_addrs, int port) {
    FILE *rfile = NULL;
    char rline[256] = {0};
    char *str = NULL;
    int n = 0;

    if ((addrs == NULL) || (max_addrs <= 0)) {
        return 0;
    }

    if ((rfile = fopen("/etc/resolv.conf", "rt")) == NULL) {
        return 0;
    }

    while (fgets(rline, sizeof(rline) - 1, rfile)) {
        if (strncmp(rline, "nameserver", 10) == 0) {
            str = strtok(rline, " ");
            str = strtok(NULL, "\n");
            if ((str != NULL) && (n < max_addrs)) {
                if (load_dns_servers_from_string(&addrs[n], port, str) == 0) {
                    n++;
                }
            }
        }
    }

    fclose(rfile);

    return n;
}
#endif

// Send a DNS query
static int send_mdns_query(char *record_name, char *query_name, char *query_server, bool inet6) {
    int query_id = 0;
    sockaddr_st servers[32] = {0};
    int nservers = 0;
    size_t capacity = 0;
    void *buffer = NULL;
    void *user_data = NULL;
    int query_type = 0;
    int isock = 0, ret = 0, idx = 0;

    if ((record_name == NULL) || (query_name == NULL) || (query_server == NULL)) {
        return -1;
    }

    if (load_dns_servers_from_string(&(servers[nservers++]), MDNS_PORT, query_server) != 0) {
        MY_ERROR("Invalid DNS server: %s", query_server);
        return -1;
    }

    isock = mdns_socket_open(inet6);
    if (isock < 0) {
        MY_ERROR("Failed to open any client sockets!");
        return -1;
    }

#ifdef _WIN32
    query_id = GetCurrentProcessId();
#else
    query_id = getpid();
#endif

    capacity = 2048;
    buffer = malloc(capacity);
    user_data = 0;

    if (strcmp(record_name, "SRV") == 0) {
        query_type = MDNS_RECORDTYPE_SRV;
    } else if (strcmp(record_name, "A") == 0) {
        query_type = MDNS_RECORDTYPE_A;
    } else if (strcmp(record_name, "AAAA") == 0) {
        query_type = MDNS_RECORDTYPE_AAAA;
    } else {
        query_type = MDNS_RECORDTYPE_PTR;
    }
    MY_DEBUG("Sending DNS query : [%s] [%s]", query_name, record_name);
    for (idx = 0; idx < nservers; idx++) {
        ret = mdns_query_send(isock, &(servers[idx].saddr), servers[idx].addrlen, query_type, query_name, buffer,
                              capacity, query_id);
        if (query_id != ret) {
            MY_DEBUG("Failed to send DNS query!");
            continue;
        }
        MY_DEBUG("Reading DNS query replies.");
        ret = mdns_query_recv(isock, buffer, capacity, mdns_query_callback, user_data, query_id);
        if (ret < 0) {
            MY_DEBUG("Failed to read DNS query reply!");
            continue;
        }
        MY_DEBUG("Read %d records", ret);
        // break;
    }

    free(buffer);
    mdns_socket_close(isock);
    return 0;
}

#define PRINT_LOG(FMT, ...) fprintf(stderr, FMT, ##__VA_ARGS__)
#define PRINT_LOGN(FMT, ...) fprintf(stderr, FMT "\n", ##__VA_ARGS__)
void print_usage(const char *exe) {
    PRINT_LOGN("Usage: %s [OPTION] <HOST> ...", exe);
    PRINT_LOGN("Options:");
    PRINT_LOGN("\t-h, --help\t\t\tShow this help");
    PRINT_LOGN("\t-t, --type <type>\t\tQuery type (PTR, SRV, A, AAAA)");
    PRINT_LOGN("\t-s, --server <server>\t\tDNS server address");
    PRINT_LOGN("\t-4, --ipv4\t\t\tQuery use IPv4");
    PRINT_LOGN("\t-6, --ipv6\t\t\tQuery use IPv6");
}

int main(int argc, const char *const *argv) {
    int ret = 0;
    char *query_type = "A";
    char *query_name = NULL;
    char *query_server = NULL;
    bool ipv6 = false;
    bool help = false;

    int opt = 0, opt_index = 0;

    static struct option long_options[] = {{"help", no_argument, 0, 'h'},         {"type", required_argument, 0, 't'},
                                           {"server", required_argument, 0, 's'}, {"ipv4", no_argument, 0, '4'},
                                           {"ipv6", no_argument, 0, '6'},         {0, 0, 0, 0}};

    while ((opt = getopt_long(argc, argv, "t:s:46h", long_options, &opt_index)) != -1) {
        switch (opt) {
            case 0:
                if (strcmp("type", long_options[opt_index].name) == 0) {
                    query_type = optarg;
                }
                if (strcmp("server", long_options[opt_index].name) == 0) {
                    query_server = optarg;
                }
                if (strcmp("ipv4", long_options[opt_index].name) == 0) {
                    ipv6 = false;
                }
                if (strcmp("ipv6", long_options[opt_index].name) == 0) {
                    ipv6 = true;
                }
                if (strcmp("help", long_options[opt_index].name) == 0) {
                    help = true;
                }
                break;
            case 't':
                query_type = optarg;
                break;
            case 's':
                query_server = optarg;
                break;
            case '4':
                ipv6 = false;
                break;
            case '6':
                ipv6 = true;
                break;
            case 'h':
                help = true;
                break;
            default:
                PRINT_LOG("Unknown option -- %c\n", opt);
                help = true;
                goto end;
        }
    }

    // MY_DEBUG("optind: %d:%d", optind, argc);
    if (optind >= argc) {
        PRINT_LOGN("No hostname specified!");
        help = true;
        goto end;
    }
    query_name = argv[optind];
    if (query_name == NULL) {
        PRINT_LOGN("Invalid hostname!");
        help = true;
        goto end;
    }

    if (query_server == NULL) {
        if (ipv6) {
            query_server = "240c::6666";
        } else {
            query_server = "223.5.5.5";
        }
    }

    MY_DEBUG("Query name: %s", query_name);
    MY_DEBUG("Query type: %s", query_type);
    MY_DEBUG("Query server: %s", query_server);
    MY_DEBUG("IPv6: %d", ipv6);

#ifdef _WIN32
    WORD versionWanted = MAKEWORD(1, 1);
    WSADATA wsaData = {0};
    if (WSAStartup(versionWanted, &wsaData)) {
        MY_ERROR("Failed to initialize WinSock!");
        ret = -1;
        goto end;
    }
#endif

    ret = send_mdns_query(query_type, query_name, query_server, ipv6);

#ifdef _WIN32
    WSACleanup();
#endif

end:
    if (help) {
        print_usage(argv[0]);
    }
    return ret;
}