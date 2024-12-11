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

#define MDNS_BUFFER_LEN 2048

typedef struct {
    struct sockaddr_storage saddr;
    size_t addrlen;
} sockaddr_st;

static int load_dns_servers_from_string(sockaddr_st *addr, uint16_t port, const char *src) {
    struct sockaddr_in *in = NULL;
    struct sockaddr_in6 *in6 = NULL;
    size_t *slen = NULL;

    if ((addr == NULL) || (src == NULL)) {
        return -1;
    }

    in = (struct sockaddr_in *)&(addr->saddr);
    in6 = (struct sockaddr_in6 *)&(addr->saddr);
    slen = &(addr->addrlen);

    if (mdns_ipv4addr_from_string(in, src) != NULL) {
        in->sin_family = AF_INET;
        in->sin_port = htons((uint16_t)port);
        *slen = sizeof(struct sockaddr_in);
        MY_DEBUG("Load dns server: %s", src);
        return 0;
    } else if (mdns_ipv6addr_from_string(in6, src) != NULL) {
        in6->sin6_family = AF_INET6;
        in6->sin6_port = htons((uint16_t)port);
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
static int load_dns_servers(sockaddr_st *addrs, int max_addrs, uint16_t port) {
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

static int print_mdns_records(char *record_name, char *query_name, char *query_server, mdns_record_t *result,
                              size_t count) {
    int idx = 0;
    mdns_record_t *record = NULL;
    mdns_record_a_t *reca = NULL;
    mdns_record_aaaa_t *recaaaa = NULL;
    char addr_buffer[256] = {0};
    mdns_string_t addr_string = {0};
    if ((record_name == NULL) || (query_name == NULL) || (query_server == NULL) || (result == NULL) || (count == 0)) {
        return -1;
    }

    printf("Query:  %s\n", query_name);
    printf("Server: %s\n", query_server);
    printf("Type:   %s\n", record_name);
    printf("Record: %u\n", count);

    for (idx = 0; idx < count; idx++) {
        record = &(result[idx]);
        memset(addr_buffer, 0, sizeof(addr_buffer));
        switch (record->type) {
            case MDNS_RECORDTYPE_A:
                reca = &(record->data.a);
                addr_string =
                    mdns_ipv4addr_to_string(addr_buffer, sizeof(addr_buffer), &(reca->addr), sizeof(reca->addr));
                printf("\tName:    %.*s\n", MDNS_STRING_FORMAT(record->name));
                printf("\tAddress: %.*s\n", MDNS_STRING_FORMAT(addr_string));
                break;
            case MDNS_RECORDTYPE_AAAA:
                recaaaa = &(record->data.aaaa);
                addr_string =
                    mdns_ipv6addr_to_string(addr_buffer, sizeof(addr_buffer), &(recaaaa->addr), sizeof(recaaaa->addr));
                printf("\tName:    %.*s\n", MDNS_STRING_FORMAT(record->name));
                printf("\tAddress: %.*s\n", MDNS_STRING_FORMAT(addr_string));
                break;
            default:
                break;
        }
    }
}

// Send a DNS query
static int send_mdns_query(char *record_name, char *query_name, char *query_server, bool inet6) {
    int ret = 0;
    sockaddr_st servers = {0};
    size_t length = MDNS_BUFFER_LEN;
    void *buffer = NULL;
    size_t count = 0;
    mdns_record_t *result = NULL;
    int query_type = 0;
    int query_id = 0;
    int isock = -1;

    if ((record_name == NULL) || (query_name == NULL) || (query_server == NULL)) {
        ret = -1;
        goto end;
    }

    if (load_dns_servers_from_string(&servers, MDNS_PORT, query_server) != 0) {
        MY_ERROR("Invalid DNS server: %s", query_server);
        ret = -1;
        goto end;
    }

    isock = mdns_socket_open(inet6);
    if (isock < 0) {
        MY_ERROR("Failed to open any client sockets!");
        ret = -1;
        goto end;
    }

#ifdef _WIN32
    query_id = GetCurrentProcessId();
#else
    query_id = getpid();
#endif

    buffer = malloc(length);
    memset(buffer, length, 0);

    if (strcmp(record_name, "AAAA") == 0) {
        query_type = MDNS_RECORDTYPE_AAAA;
    } else {
        query_type = MDNS_RECORDTYPE_A;
        record_name = "A";
    }
    MY_DEBUG("Sending DNS query: [%s] [%s]", query_name, record_name);

    ret = mdns_query_send(isock, &(servers.saddr), servers.addrlen, query_type, query_name, query_id, buffer, length);
    if (query_id != ret) {
        MY_DEBUG("Failed to send DNS query!");
        ret = -1;
        goto end;
    }
    MY_DEBUG("Reading DNS query replies.");
    ret = mdns_query_recv(isock, buffer, length, query_type, query_id, &result, &count);
    if (ret < 0) {
        MY_DEBUG("Failed to read DNS query reply!");
        ret = -1;
        goto end;
    }
    MY_DEBUG("Read %d:%d records", ret, count);
    if ((result == NULL) || (count == 0)) {
        MY_ERROR("No record found for DNS query: [%s] [%s]", query_name, record_name);
        ret = -1;
        goto end;
    }

    ret = print_mdns_records(record_name, query_name, query_server, result, count);
end:
    if (isock >= 0) {
        mdns_socket_close(isock);
    }
    if (buffer) {
        free(buffer);
    }
    if (result != NULL) {
        free(result);
    }
    return 0;
}

#define PRINT_LOG(FMT, ...) fprintf(stderr, FMT, ##__VA_ARGS__)
#define PRINT_LOGN(FMT, ...) fprintf(stderr, FMT "\n", ##__VA_ARGS__)
void print_usage(const char *exe) {
    PRINT_LOGN("Usage: %s [OPTION] <HOST> ...", exe);
    PRINT_LOGN("Options:");
    PRINT_LOGN("\t-h, --help\t\t\tShow this help");
    PRINT_LOGN("\t-t, --type <type>\t\tQuery type (A, AAAA)");
    PRINT_LOGN("\t-s, --server <server>\t\tDNS server address");
    PRINT_LOGN("\t-4, --inet4\t\t\tQuery use IPv4");
    PRINT_LOGN("\t-6, --inet6\t\t\tQuery use IPv6");
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
                                           {"server", required_argument, 0, 's'}, {"inet4", no_argument, 0, '4'},
                                           {"inet4", no_argument, 0, '6'},        {0, 0, 0, 0}};

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