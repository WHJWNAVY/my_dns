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

/* The function obtains the DNS servers stored in /etc/resolv.conf */
static int load_dns_servers(sockaddr_st *addrs, int max_addrs, int port) {
    FILE *rfile = NULL;
    char rline[256] = {0};
    struct sockaddr_in *in = NULL;
    struct sockaddr_in6 *in6 = NULL;
    size_t *slen = NULL;
    char *str = NULL;
    int n = 0;

    if ((rfile = fopen("/etc/resolv.conf", "rt")) == NULL) {
        return 0;
    }

    while (fgets(rline, sizeof(rline) - 1, rfile)) {
        if (strncmp(rline, "nameserver", 10) == 0) {
            str = strtok(rline, " ");
            str = strtok(NULL, "\n");
            if ((str != NULL) && (n < max_addrs)) {
                in = (struct sockaddr_in *)&(addrs[n].saddr);
                in6 = (struct sockaddr_in6 *)&(addrs[n].saddr);
                slen = &(addrs[n].addrlen);
                if (ipv4_address_from_string(in, str) != NULL) {
                    in->sin_family = AF_INET;
                    in->sin_port = htons((unsigned short)port);
                    *slen = sizeof(struct sockaddr_in);
                    printf("Load dns server: %s\n", str);
                    n++;
                } else if (ipv6_address_from_string(&(addrs[n].saddr), str) != NULL) {
                    in6->sin6_family = AF_INET6;
                    in6->sin6_port = htons((unsigned short)port);
                    *slen = sizeof(struct sockaddr_in6);
                    printf("Load dns6 server: %s\n", str);
                    n++;
                }
            }
        }
    }

    fclose(rfile);

    return n;
}

// Open sockets for sending one-shot multicast queries from an ephemeral port
static int open_client_sockets(int *sockets, int max_sockets, int port) {
    // When sending, each socket can only send to one network interface
    // Thus we need to open one socket for each interface and address family
    int num_sockets = 0;

#ifdef _WIN32
    IP_ADAPTER_ADDRESSES *adapter_address = 0;
    ULONG address_size = 8000;
    unsigned int ret;
    unsigned int num_retries = 4;
    do {
        adapter_address = (IP_ADAPTER_ADDRESSES *)malloc(address_size);
        ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, 0, adapter_address,
                                   &address_size);
        if (ret == ERROR_BUFFER_OVERFLOW) {
            free(adapter_address);
            adapter_address = 0;
            address_size *= 2;
        } else {
            break;
        }
    } while (num_retries-- > 0);

    if (!adapter_address || (ret != NO_ERROR)) {
        free(adapter_address);
        printf("Failed to get network adapter addresses\n");
        return num_sockets;
    }

    int first_ipv4 = 1;
    int first_ipv6 = 1;
    for (PIP_ADAPTER_ADDRESSES adapter = adapter_address; adapter; adapter = adapter->Next) {
        if (adapter->TunnelType == TUNNEL_TYPE_TEREDO)
            continue;
        if (adapter->OperStatus != IfOperStatusUp)
            continue;

        for (IP_ADAPTER_UNICAST_ADDRESS *unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next) {
            if (unicast->Address.lpSockaddr->sa_family == AF_INET) {
                struct sockaddr_in *saddr = (struct sockaddr_in *)unicast->Address.lpSockaddr;
                if ((saddr->sin_addr.S_un.S_un_b.s_b1 != 127) || (saddr->sin_addr.S_un.S_un_b.s_b2 != 0) ||
                    (saddr->sin_addr.S_un.S_un_b.s_b3 != 0) || (saddr->sin_addr.S_un.S_un_b.s_b4 != 1)) {
                    int log_addr = 0;
                    if (first_ipv4) {
                        service_address_ipv4 = *saddr;
                        first_ipv4 = 0;
                        log_addr = 1;
                    }
                    has_ipv4 = 1;
                    if (num_sockets < max_sockets) {
                        saddr->sin_port = htons((unsigned short)port);
                        int sock = mdns_socket_open_ipv4(saddr);
                        if (sock >= 0) {
                            sockets[num_sockets++] = sock;
                            log_addr = 1;
                        } else {
                            log_addr = 0;
                        }
                    }
                    if (log_addr) {
                        char buffer[128];
                        mdns_string_t addr =
                            ipv4_address_to_string(buffer, sizeof(buffer), saddr, sizeof(struct sockaddr_in));
                        printf("Local IPv4 address: %.*s\n", MDNS_STRING_FORMAT(addr));
                    }
                }
            } else if (unicast->Address.lpSockaddr->sa_family == AF_INET6) {
                struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)unicast->Address.lpSockaddr;
                // Ignore link-local addresses
                if (saddr->sin6_scope_id)
                    continue;
                static const unsigned char localhost[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
                static const unsigned char localhost_mapped[] = {0, 0, 0,    0,    0,    0, 0, 0,
                                                                 0, 0, 0xff, 0xff, 0x7f, 0, 0, 1};
                if ((unicast->DadState == NldsPreferred) && memcmp(saddr->sin6_addr.s6_addr, localhost, 16) &&
                    memcmp(saddr->sin6_addr.s6_addr, localhost_mapped, 16)) {
                    int log_addr = 0;
                    if (first_ipv6) {
                        service_address_ipv6 = *saddr;
                        first_ipv6 = 0;
                        log_addr = 1;
                    }
                    has_ipv6 = 1;
                    if (num_sockets < max_sockets) {
                        saddr->sin6_port = htons((unsigned short)port);
                        int sock = mdns_socket_open_ipv6(saddr);
                        if (sock >= 0) {
                            sockets[num_sockets++] = sock;
                            log_addr = 1;
                        } else {
                            log_addr = 0;
                        }
                    }
                    if (log_addr) {
                        char buffer[128];
                        mdns_string_t addr =
                            ipv6_address_to_string(buffer, sizeof(buffer), saddr, sizeof(struct sockaddr_in6));
                        printf("Local IPv6 address: %.*s\n", MDNS_STRING_FORMAT(addr));
                    }
                }
            }
        }
    }

    free(adapter_address);
#else
    struct ifaddrs *ifaddr = 0;
    struct ifaddrs *ifa = 0;

    if (getifaddrs(&ifaddr) < 0)
        printf("Unable to get interface addresses\n");

    int first_ipv4 = 1;
    int first_ipv6 = 1;
    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr)
            continue;
        if (!(ifa->ifa_flags & IFF_UP) || !(ifa->ifa_flags & IFF_MULTICAST))
            continue;
        if ((ifa->ifa_flags & IFF_LOOPBACK) || (ifa->ifa_flags & IFF_POINTOPOINT))
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *saddr = (struct sockaddr_in *)ifa->ifa_addr;
            if (saddr->sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
                int log_addr = 0;
                if (first_ipv4) {
                    service_address_ipv4 = *saddr;
                    first_ipv4 = 0;
                    log_addr = 1;
                }
                has_ipv4 = 1;
                if (num_sockets < max_sockets) {
                    saddr->sin_port = htons(port);
                    int sock = mdns_socket_open_ipv4(saddr);
                    if (sock >= 0) {
                        sockets[num_sockets++] = sock;
                        log_addr = 1;
                    } else {
                        log_addr = 0;
                    }
                }
                if (log_addr) {
                    char buffer[128];
                    mdns_string_t addr =
                        ipv4_address_to_string(buffer, sizeof(buffer), saddr, sizeof(struct sockaddr_in));
                    printf("Local IPv4 address: %.*s\n", MDNS_STRING_FORMAT(addr));
                }
            }
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)ifa->ifa_addr;
            // Ignore link-local addresses
            if (saddr->sin6_scope_id)
                continue;
            static const unsigned char localhost[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
            static const unsigned char localhost_mapped[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x7f, 0, 0, 1};
            if (memcmp(saddr->sin6_addr.s6_addr, localhost, 16) &&
                memcmp(saddr->sin6_addr.s6_addr, localhost_mapped, 16)) {
                int log_addr = 0;
                if (first_ipv6) {
                    service_address_ipv6 = *saddr;
                    first_ipv6 = 0;
                    log_addr = 1;
                }
                has_ipv6 = 1;
                if (num_sockets < max_sockets) {
                    saddr->sin6_port = htons(port);
                    int sock = mdns_socket_open_ipv6(saddr);
                    if (sock >= 0) {
                        sockets[num_sockets++] = sock;
                        log_addr = 1;
                    } else {
                        log_addr = 0;
                    }
                }
                if (log_addr) {
                    char buffer[128];
                    mdns_string_t addr =
                        ipv6_address_to_string(buffer, sizeof(buffer), saddr, sizeof(struct sockaddr_in6));
                    printf("Local IPv6 address: %.*s\n", MDNS_STRING_FORMAT(addr));
                }
            }
        }
    }

    freeifaddrs(ifaddr);
#endif
    return num_sockets;
}

// Send a mDNS query
static int send_mdns_query(mdns_query_t *query, size_t count) {
    int sockets[32] = {0};
    int query_id[32] = {0};
    sockaddr_st servers[32] = {0};
    size_t capacity = 0;
    void *buffer = NULL;
    void *user_data = NULL;
    size_t iq = 0, rec = 0;
    int res = 0, nfds = 0, records = 0;
    int isock = 0, iserv = 0;
    struct timeval timeout = {0};
    fd_set readfs = {0};

    int num_servers = load_dns_servers(&servers, sizeof(servers) / sizeof(servers[0]), MDNS_PORT);
    if (num_servers <= 0) {
        printf("Failed to load DNS servers\n");
        return -1;
    }
    printf("Loaded %d DNS server%s\n", num_servers, num_servers > 1 ? "s" : "");

    int num_sockets = open_client_sockets(sockets, sizeof(sockets) / sizeof(sockets[0]), 0);
    if (num_sockets <= 0) {
        printf("Failed to open any client sockets\n");
        return -1;
    }
    printf("Opened %d socket%s for mDNS query\n", num_sockets, num_sockets > 1 ? "s" : "");

    capacity = 2048;
    buffer = malloc(capacity);
    user_data = 0;

    printf("Sending mDNS query");
    for (iq = 0; iq < count; ++iq) {
        const char *record_name = "PTR";
        if (query[iq].type == MDNS_RECORDTYPE_SRV)
            record_name = "SRV";
        else if (query[iq].type == MDNS_RECORDTYPE_A)
            record_name = "A";
        else if (query[iq].type == MDNS_RECORDTYPE_AAAA)
            record_name = "AAAA";
        else
            query[iq].type = MDNS_RECORDTYPE_PTR;
        printf(" : %s %s", query[iq].name, record_name);
    }
    printf("\n");
    for (isock = 0; isock < num_sockets; ++isock) {
        query_id[isock] = mdns_multiquery_send(sockets[isock], &(servers[0].saddr), servers[0].addrlen, query, count,
                                               buffer, capacity, 0);
        if (query_id[isock] < 0)
            printf("Failed to send mDNS query: %s\n", strerror(errno));
    }

    // This is a simple implementation that loops for 5 seconds or as long as we get replies
    printf("Reading mDNS query replies\n");
    do {
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;
        FD_ZERO(&readfs);
        for (isock = 0; isock < num_sockets; ++isock) {
            if (sockets[isock] >= nfds)
                nfds = sockets[isock] + 1;
            FD_SET(sockets[isock], &readfs);
        }

        res = select(nfds, &readfs, 0, 0, &timeout);
        if (res > 0) {
            for (isock = 0; isock < num_sockets; ++isock) {
                if (FD_ISSET(sockets[isock], &readfs)) {
                    rec = mdns_query_recv(sockets[isock], buffer, capacity, mdns_query_callback, user_data,
                                          query_id[isock]);
                    if (rec > 0)
                        records += rec;
                }
                FD_SET(sockets[isock], &readfs);
            }
        }
    } while (res > 0);

    printf("Read %d records\n", records);

    free(buffer);

    for (isock = 0; isock < num_sockets; ++isock)
        mdns_socket_close(sockets[isock]);
    printf("Closed socket%s\n", num_sockets > 1 ? "s" : "");

    return 0;
}

void usage(const char *exe) {
    fprintf(stderr, "Usage: %s --query [TYPE] <HOST> ...\n", exe);
    fprintf(stderr, "Query types:\n");
    fprintf(stderr, "\tPTR\t- Service name\n");
    fprintf(stderr, "\tSRV\t- Service instance\n");
    fprintf(stderr, "\tA\t- IPv4 address\n");
    fprintf(stderr, "\tAAAA\t- IPv6 address\n");
}

int main(int argc, const char *const *argv) {
    int ret = 0;
    mdns_query_t query[16] = {0};
    size_t query_count = 0;

#ifdef _WIN32
    WORD versionWanted = MAKEWORD(1, 1);
    WSADATA wsaData;
    if (WSAStartup(versionWanted, &wsaData)) {
        printf("Failed to initialize WinSock\n");
        return -1;
    }
#endif

    for (int iarg = 0; iarg < argc; ++iarg) {
        if (strcmp(argv[iarg], "--query") == 0) {
            // Each query is either a service name, or a pair of record type and a service name
            ++iarg;
            while ((iarg < argc) && (query_count < 16)) {
                query[query_count].name = argv[iarg++];
                query[query_count].type = MDNS_RECORDTYPE_PTR;
                if (iarg < argc) {
                    mdns_record_type_t record_type = 0;
                    if (strcmp(query[query_count].name, "PTR") == 0)
                        record_type = MDNS_RECORDTYPE_PTR;
                    else if (strcmp(query[query_count].name, "SRV") == 0)
                        record_type = MDNS_RECORDTYPE_SRV;
                    else if (strcmp(query[query_count].name, "A") == 0)
                        record_type = MDNS_RECORDTYPE_A;
                    else if (strcmp(query[query_count].name, "AAAA") == 0)
                        record_type = MDNS_RECORDTYPE_AAAA;
                    if (record_type != 0) {
                        query[query_count].type = record_type;
                        query[query_count].name = argv[iarg++];
                    }
                }
                query[query_count].length = strlen(query[query_count].name);
                ++query_count;
            }
        }
    }

    if (query_count <= 0) {
        usage(argv[0]);
        goto err;
    }

    ret = send_mdns_query(query, query_count);

err:
#ifdef _WIN32
    WSACleanup();
#endif

    return ret;
}