#ifndef _MY_DNS_H_
#define _MY_DNS_H_

// #ifdef _WIN32
// #undef _WIN32
// #endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include <fcntl.h>
#ifdef _WIN32
#include <Winsock2.h>
#include <Ws2tcpip.h>
#define strncasecmp _strnicmp
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "my_debug.h"
#include "my_getopt.h"

#define MDNS_INVALID_POS ((size_t) - 1)

#define MDNS_STRING_CONST(s) (s), (sizeof((s)) - 1)
#define MDNS_STRING_ARGS(s) s.str, s.length
#define MDNS_STRING_FORMAT(s) (int)((s).length), s.str

#define MDNS_POINTER_OFFSET(p, ofs) ((void *)((char *)(p) + (ptrdiff_t)(ofs)))
#define MDNS_POINTER_OFFSET_CONST(p, ofs) ((const void *)((const char *)(p) + (ptrdiff_t)(ofs)))
#define MDNS_POINTER_DIFF(a, b) ((size_t)((const char *)(a) - (const char *)(b)))

#define MDNS_PORT 53
#define MDNS_MAX_TIMEOUS 10
#define MDNS_MAX_SUBSTRINGS 64

enum mdns_record_type {
    MDNS_RECORDTYPE_IGNORE = 0,
    // Address
    MDNS_RECORDTYPE_A = 1,
    // Domain Name pointer
    MDNS_RECORDTYPE_PTR = 12,
    // Arbitrary text string
    MDNS_RECORDTYPE_TXT = 16,
    // IP6 Address [Thomson]
    MDNS_RECORDTYPE_AAAA = 28,
    // Server Selection [RFC2782]
    MDNS_RECORDTYPE_SRV = 33,
    // Any available records
    MDNS_RECORDTYPE_ANY = 255
};

enum mdns_entry_type {
    MDNS_ENTRYTYPE_QUESTION = 0,
    MDNS_ENTRYTYPE_ANSWER = 1,
    MDNS_ENTRYTYPE_AUTHORITY = 2,
    MDNS_ENTRYTYPE_ADDITIONAL = 3
};

enum mdns_class { MDNS_CLASS_IN = 1, MDNS_CLASS_ANY = 255 };

typedef enum mdns_record_type mdns_record_type_t;
typedef enum mdns_entry_type mdns_entry_type_t;
typedef enum mdns_class mdns_class_t;

typedef int (*mdns_record_callback_fn)(int sock, const struct sockaddr *from, size_t addrlen, mdns_entry_type_t entry,
                                       uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl,
                                       const void *data, size_t size, size_t name_offset, size_t name_length,
                                       size_t record_offset, size_t record_length, void *user_data);

typedef struct mdns_string_t mdns_string_t;
typedef struct mdns_string_pair_t mdns_string_pair_t;
typedef struct mdns_string_table_item_t mdns_string_table_item_t;
typedef struct mdns_string_table_t mdns_string_table_t;
typedef struct mdns_record_t mdns_record_t;
typedef struct mdns_record_srv_t mdns_record_srv_t;
typedef struct mdns_record_ptr_t mdns_record_ptr_t;
typedef struct mdns_record_a_t mdns_record_a_t;
typedef struct mdns_record_aaaa_t mdns_record_aaaa_t;
typedef struct mdns_record_txt_t mdns_record_txt_t;
typedef struct mdns_query_t mdns_query_t;

#ifdef _WIN32
typedef int mdns_size_t;
typedef int mdns_ssize_t;
#else
typedef size_t mdns_size_t;
typedef ssize_t mdns_ssize_t;
#endif

struct mdns_string_t {
    const char *str;
    size_t length;
};

struct mdns_string_pair_t {
    size_t offset;
    size_t length;
    int ref;
};

struct mdns_string_table_t {
    size_t offset[16];
    size_t count;
    size_t next;
};

struct mdns_record_srv_t {
    uint16_t priority;
    uint16_t weight;
    uint16_t port;
    mdns_string_t name;
};

struct mdns_record_ptr_t {
    mdns_string_t name;
};

struct mdns_record_a_t {
    struct sockaddr_in addr;
};

struct mdns_record_aaaa_t {
    struct sockaddr_in6 addr;
};

struct mdns_record_txt_t {
    mdns_string_t key;
    mdns_string_t value;
};

struct mdns_record_t {
    mdns_string_t name;
    mdns_record_type_t type;
    union mdns_record_data {
        mdns_record_ptr_t ptr;
        mdns_record_srv_t srv;
        mdns_record_a_t a;
        mdns_record_aaaa_t aaaa;
        mdns_record_txt_t txt;
    } data;
    uint16_t rclass;
    uint32_t ttl;
};

struct mdns_header_t {
    uint16_t query_id;
    uint16_t flags;
    uint16_t questions;
    uint16_t answer_rrs;
    uint16_t authority_rrs;
    uint16_t additional_rrs;
};

struct mdns_query_t {
    mdns_record_type_t type;
    const char *name;
    size_t length;
};

// mDNS/DNS-SD public API

// ! Open a socket for sending and receiving DNS packets. Returns a valid socket on success, or -1 on error.
static inline int mdns_socket_open(bool inet6);

// ! Setup a socket for sending and receiving DNS packets. Returns 0 on success, or <0 on error.
static inline int mdns_socket_setup(int sock, bool inet6);

//! Close a socket opened with mdns_socket_open.
static inline void mdns_socket_close(int sock);

//! Send a multicast mDNS query on the given socket for the given service name. The supplied buffer
//! will be used to build the query packet and must be 32 bit aligned. The query ID can be set to
//! non-zero to filter responses, however the RFC states that the query ID SHOULD be set to 0 for
//! multicast queries. The query will request a unicast response if the socket is bound to an
//! ephemeral port, or a multicast response if the socket is bound to mDNS port 5353. Returns the
//! used query ID, or <0 if error.
static inline int mdns_query_send(int sock, const void *saddr, size_t saddrlen, mdns_record_type_t type,
                                  const char *name, void *buffer, size_t capacity, uint16_t query_id);

//! Send a multicast mDNS query on the given socket for the given service names. The supplied buffer
//! will be used to build the query packet and must be 32 bit aligned. The query ID can be set to
//! non-zero to filter responses, however the RFC states that the query ID SHOULD be set to 0 for
//! multicast queries. Each additional service name query consists of a triplet - a record type
//! (mdns_record_type_t), a name string pointer (const char*) and a name length (size_t). The list
//! of variable arguments should be terminated with a record type of 0. The query will request a
//! unicast response if the socket is bound to an ephemeral port, or a multicast response if the
//! socket is bound to mDNS port 5353. Returns the used query ID, or <0 if error.
static inline int mdns_multiquery_send(int sock, const void *saddr, size_t saddrlen, const mdns_query_t *query,
                                       size_t count, void *buffer, size_t capacity, uint16_t query_id);

//! Receive unicast responses to a mDNS query sent with mdns_[multi]query_send, optionally filtering
//! out any responses not matching the given query ID. Set the query ID to 0 to parse all responses,
//! even if it is not matching the query ID set in a specific query. Any data will be piped to the
//! given callback for parsing. Buffer must be 32 bit aligned. Parsing is stopped when callback
//! function returns non-zero. Returns the number of responses parsed.
static inline size_t mdns_query_recv(int sock, void *buffer, size_t capacity, mdns_record_callback_fn callback,
                                     void *user_data, int query_id);

// Parse records functions

//! Parse a PTR record, returns the name in the record
static inline mdns_string_t mdns_record_parse_ptr(const void *buffer, size_t size, size_t offset, size_t length,
                                                  char *strbuffer, size_t capacity);

//! Parse a SRV record, returns the priority, weight, port and name in the record
static inline mdns_record_srv_t mdns_record_parse_srv(const void *buffer, size_t size, size_t offset, size_t length,
                                                      char *strbuffer, size_t capacity);

//! Parse an A record, returns the IPv4 address in the record
static inline struct sockaddr_in *mdns_record_parse_a(const void *buffer, size_t size, size_t offset, size_t length,
                                                      struct sockaddr_in *addr);

//! Parse an AAAA record, returns the IPv6 address in the record
static inline struct sockaddr_in6 *mdns_record_parse_aaaa(const void *buffer, size_t size, size_t offset, size_t length,
                                                          struct sockaddr_in6 *addr);

//! Parse a TXT record, returns the number of key=value records parsed and stores the key-value
//! pairs in the supplied buffer
static inline size_t mdns_record_parse_txt(const void *buffer, size_t size, size_t offset, size_t length,
                                           mdns_record_txt_t *records, size_t capacity);

// Internal functions

static inline mdns_string_t mdns_string_extract(const void *buffer, size_t size, size_t *offset, char *str,
                                                size_t capacity);

static inline int mdns_string_skip(const void *buffer, size_t size, size_t *offset);

static inline size_t mdns_string_find(const char *str, size_t length, char c, size_t offset);

//! Compare if two strings are equal. If the strings are equal it returns >0 and the offset
//! variables are updated to the end of the corresponding strings. If the strings are not equal it
//! returns 0 and the offset variables are NOT updated.
static inline int mdns_string_equal(const void *buffer_lhs, size_t size_lhs, size_t *ofs_lhs, const void *buffer_rhs,
                                    size_t size_rhs, size_t *ofs_rhs);

static inline void *mdns_string_make(void *buffer, size_t capacity, void *data, const char *name, size_t length,
                                     mdns_string_table_t *string_table);

static inline size_t mdns_string_table_find(mdns_string_table_t *string_table, const void *buffer, size_t capacity,
                                            const char *str, size_t first_length, size_t total_length);

// Implementations

static inline uint16_t mdns_ntohs(const void *data) {
    uint16_t aligned;
    memcpy(&aligned, data, sizeof(uint16_t));
    return ntohs(aligned);
}

static inline uint32_t mdns_ntohl(const void *data) {
    uint32_t aligned;
    memcpy(&aligned, data, sizeof(uint32_t));
    return ntohl(aligned);
}

static inline void *mdns_htons(void *data, uint16_t val) {
    val = htons(val);
    memcpy(data, &val, sizeof(uint16_t));
    return MDNS_POINTER_OFFSET(data, sizeof(uint16_t));
}

static inline void *mdns_htonl(void *data, uint32_t val) {
    val = htonl(val);
    memcpy(data, &val, sizeof(uint32_t));
    return MDNS_POINTER_OFFSET(data, sizeof(uint32_t));
}

static inline int mdns_socket_setup(int sock, bool inet6) {
    unsigned int reuseaddr = 1;
    struct sockaddr_storage sock_addr = {0};
    struct sockaddr_in *in_addr = (struct sockaddr_in *)(&sock_addr);
    struct sockaddr_in6 *in6_addr = (struct sockaddr_in6 *)(&sock_addr);

    struct timeval so_timeout = {.tv_sec = MDNS_MAX_TIMEOUS, .tv_usec = 0};

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuseaddr, sizeof(reuseaddr)) != 0) {
        MY_ERROR("Failed to set reuseaddr: %d, %s", errno, strerror(errno));
        return -1;
    }
#ifdef SO_REUSEPORT
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char *)&reuseaddr, sizeof(reuseaddr)) != 0) {
        MY_ERROR("Failed to set reuseport: %d, %s", errno, strerror(errno));
        return -1;
    }
#endif
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &so_timeout, sizeof(so_timeout)) != 0) {
        MY_ERROR("Failed to set recv timeout: %d, %s", errno, strerror(errno));
        return -1;
    }
#if 0
    if (inet6) {
        in6_addr->sin6_family = AF_INET6;
        in6_addr->sin6_addr = in6addr_any;
        in6_addr->sin6_port = htons(0);
#ifdef __APPLE__
        in6_addr->sin6_len = sizeof(struct sockaddr_in6);
#endif
        if (bind(sock, in6_addr, sizeof(struct sockaddr_in6))) {
            MY_ERROR("Failed to bind sock to ipv6: %d, %s", errno, strerror(errno));
            return -1;
        }
    } else {
        in_addr->sin_family = AF_INET;
        in_addr->sin_addr.s_addr = htonl(INADDR_ANY);
        in_addr->sin_port = htons(0);
#ifdef __APPLE__
        in_addr->sin_len = sizeof(struct sockaddr_in);
#endif
        if (bind(sock, in_addr, sizeof(struct sockaddr_in))) {
            MY_ERROR("Failed to bind sock to ipv4: %d, %s", errno, strerror(errno));
            return -1;
        }
    }
#endif
    return 0;
}

static inline int mdns_socket_open(bool inet6) {
    unsigned int reuseaddr = 1;
    int af = (inet6 ? AF_INET6 : AF_INET);
    int sock = (int)socket(af, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        MY_ERROR("Failed to create socket: %d, %s", errno, strerror(errno));
        return -1;
    }

    if (mdns_socket_setup(sock, inet6)) {
        MY_ERROR("Failed to setup socket %d!", sock);
        mdns_socket_close(sock);
        return -1;
    }
    return sock;
}

static inline void mdns_socket_close(int sock) {
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
}

static inline int mdns_is_string_ref(uint8_t val) {
    return (0xC0 == (val & 0xC0));
}

static inline mdns_string_pair_t mdns_get_next_substring(const void *rawdata, size_t size, size_t offset) {
    const uint8_t *buffer = (const uint8_t *)rawdata;
    mdns_string_pair_t pair = {MDNS_INVALID_POS, 0, 0};
    if (offset >= size)
        return pair;
    if (!buffer[offset]) {
        pair.offset = offset;
        return pair;
    }
    int recursion = 0;
    while (mdns_is_string_ref(buffer[offset])) {
        if (size < offset + 2)
            return pair;

        offset = mdns_ntohs(MDNS_POINTER_OFFSET(buffer, offset)) & 0x3fff;
        if (offset >= size)
            return pair;

        pair.ref = 1;
        if (++recursion > 16)
            return pair;
    }

    size_t length = (size_t)buffer[offset++];
    if (size < offset + length)
        return pair;

    pair.offset = offset;
    pair.length = length;

    return pair;
}

static inline int mdns_string_skip(const void *buffer, size_t size, size_t *offset) {
    size_t cur = *offset;
    mdns_string_pair_t substr;
    unsigned int counter = 0;
    do {
        substr = mdns_get_next_substring(buffer, size, cur);
        if ((substr.offset == MDNS_INVALID_POS) || (counter++ > MDNS_MAX_SUBSTRINGS))
            return 0;
        if (substr.ref) {
            *offset = cur + 2;
            return 1;
        }
        cur = substr.offset + substr.length;
    } while (substr.length);

    *offset = cur + 1;
    return 1;
}

static inline int mdns_string_equal(const void *buffer_lhs, size_t size_lhs, size_t *ofs_lhs, const void *buffer_rhs,
                                    size_t size_rhs, size_t *ofs_rhs) {
    size_t lhs_cur = *ofs_lhs;
    size_t rhs_cur = *ofs_rhs;
    size_t lhs_end = MDNS_INVALID_POS;
    size_t rhs_end = MDNS_INVALID_POS;
    mdns_string_pair_t lhs_substr;
    mdns_string_pair_t rhs_substr;
    unsigned int counter = 0;
    do {
        lhs_substr = mdns_get_next_substring(buffer_lhs, size_lhs, lhs_cur);
        rhs_substr = mdns_get_next_substring(buffer_rhs, size_rhs, rhs_cur);
        if ((lhs_substr.offset == MDNS_INVALID_POS) || (rhs_substr.offset == MDNS_INVALID_POS) ||
            (counter++ > MDNS_MAX_SUBSTRINGS))
            return 0;
        if (lhs_substr.length != rhs_substr.length)
            return 0;
        if (strncasecmp((const char *)MDNS_POINTER_OFFSET_CONST(buffer_rhs, rhs_substr.offset),
                        (const char *)MDNS_POINTER_OFFSET_CONST(buffer_lhs, lhs_substr.offset), rhs_substr.length))
            return 0;
        if (lhs_substr.ref && (lhs_end == MDNS_INVALID_POS))
            lhs_end = lhs_cur + 2;
        if (rhs_substr.ref && (rhs_end == MDNS_INVALID_POS))
            rhs_end = rhs_cur + 2;
        lhs_cur = lhs_substr.offset + lhs_substr.length;
        rhs_cur = rhs_substr.offset + rhs_substr.length;
    } while (lhs_substr.length);

    if (lhs_end == MDNS_INVALID_POS)
        lhs_end = lhs_cur + 1;
    *ofs_lhs = lhs_end;

    if (rhs_end == MDNS_INVALID_POS)
        rhs_end = rhs_cur + 1;
    *ofs_rhs = rhs_end;

    return 1;
}

static inline mdns_string_t mdns_string_extract(const void *buffer, size_t size, size_t *offset, char *str,
                                                size_t capacity) {
    size_t cur = *offset;
    size_t end = MDNS_INVALID_POS;
    mdns_string_pair_t substr;
    mdns_string_t result;
    result.str = str;
    result.length = 0;
    char *dst = str;
    unsigned int counter = 0;
    size_t remain = capacity;
    do {
        substr = mdns_get_next_substring(buffer, size, cur);
        if ((substr.offset == MDNS_INVALID_POS) || (counter++ > MDNS_MAX_SUBSTRINGS))
            return result;
        if (substr.ref && (end == MDNS_INVALID_POS))
            end = cur + 2;
        if (substr.length) {
            size_t to_copy = (substr.length < remain) ? substr.length : remain;
            memcpy(dst, (const char *)buffer + substr.offset, to_copy);
            dst += to_copy;
            remain -= to_copy;
            if (remain) {
                *dst++ = '.';
                --remain;
            }
        }
        cur = substr.offset + substr.length;
    } while (substr.length);

    if (end == MDNS_INVALID_POS) {
        end = cur + 1;
    }
    *offset = end;

    result.length = capacity - remain;
    return result;
}

static inline size_t mdns_string_table_find(mdns_string_table_t *string_table, const void *buffer, size_t capacity,
                                            const char *str, size_t first_length, size_t total_length) {
    if (!string_table)
        return MDNS_INVALID_POS;

    for (size_t istr = 0; istr < string_table->count; ++istr) {
        if (string_table->offset[istr] >= capacity)
            continue;
        size_t offset = 0;
        mdns_string_pair_t sub_string = mdns_get_next_substring(buffer, capacity, string_table->offset[istr]);
        if (!sub_string.length || (sub_string.length != first_length))
            continue;
        if (memcmp(str, MDNS_POINTER_OFFSET(buffer, sub_string.offset), sub_string.length))
            continue;

        // Initial substring matches, now match all remaining substrings
        offset += first_length + 1;
        while (offset < total_length) {
            size_t dot_pos = mdns_string_find(str, total_length, '.', offset);
            if (dot_pos == MDNS_INVALID_POS)
                dot_pos = total_length;
            size_t current_length = dot_pos - offset;

            sub_string = mdns_get_next_substring(buffer, capacity, sub_string.offset + sub_string.length);
            if (!sub_string.length || (sub_string.length != current_length))
                break;
            if (memcmp(str + offset, MDNS_POINTER_OFFSET(buffer, sub_string.offset), sub_string.length))
                break;

            offset = dot_pos + 1;
        }

        // Return reference offset if entire string matches
        if (offset >= total_length)
            return string_table->offset[istr];
    }

    return MDNS_INVALID_POS;
}

static inline void mdns_string_table_add(mdns_string_table_t *string_table, size_t offset) {
    if (!string_table)
        return;

    string_table->offset[string_table->next] = offset;

    size_t table_capacity = sizeof(string_table->offset) / sizeof(string_table->offset[0]);
    if (++string_table->count > table_capacity)
        string_table->count = table_capacity;
    if (++string_table->next >= table_capacity)
        string_table->next = 0;
}

static inline size_t mdns_string_find(const char *str, size_t length, char c, size_t offset) {
    const void *found;
    if (offset >= length)
        return MDNS_INVALID_POS;
    found = memchr(str + offset, c, length - offset);
    if (found)
        return (size_t)MDNS_POINTER_DIFF(found, str);
    return MDNS_INVALID_POS;
}

static inline void *mdns_string_make_ref(void *data, size_t capacity, size_t ref_offset) {
    if (capacity < 2)
        return 0;
    return mdns_htons(data, 0xC000 | (uint16_t)ref_offset);
}

static inline void *mdns_string_make(void *buffer, size_t capacity, void *data, const char *name, size_t length,
                                     mdns_string_table_t *string_table) {
    size_t last_pos = 0;
    size_t remain = capacity - MDNS_POINTER_DIFF(data, buffer);
    if (name[length - 1] == '.')
        --length;
    while (last_pos < length) {
        size_t pos = mdns_string_find(name, length, '.', last_pos);
        size_t sub_length = ((pos != MDNS_INVALID_POS) ? pos : length) - last_pos;
        size_t total_length = length - last_pos;

        size_t ref_offset = mdns_string_table_find(
            string_table, buffer, capacity, (char *)MDNS_POINTER_OFFSET(name, last_pos), sub_length, total_length);
        if (ref_offset != MDNS_INVALID_POS)
            return mdns_string_make_ref(data, remain, ref_offset);

        if (remain <= (sub_length + 1))
            return 0;

        *(unsigned char *)data = (unsigned char)sub_length;
        memcpy(MDNS_POINTER_OFFSET(data, 1), name + last_pos, sub_length);
        mdns_string_table_add(string_table, MDNS_POINTER_DIFF(data, buffer));

        data = MDNS_POINTER_OFFSET(data, sub_length + 1);
        last_pos = ((pos != MDNS_INVALID_POS) ? pos + 1 : length);
        remain = capacity - MDNS_POINTER_DIFF(data, buffer);
    }

    if (!remain)
        return 0;

    *(unsigned char *)data = 0;
    return MDNS_POINTER_OFFSET(data, 1);
}

static inline size_t mdns_records_parse(int sock, const struct sockaddr *from, size_t addrlen, const void *buffer,
                                        size_t size, size_t *offset, mdns_entry_type_t type, uint16_t query_id,
                                        size_t records, mdns_record_callback_fn callback, void *user_data) {
    size_t i = 0, parsed = 0;
    size_t name_offset = 0, name_length = 0, length = 0;
    uint16_t rtype = 0, rclass = 0;
    uint32_t ttl = 0;
    const uint16_t *data = NULL;
    for (i = 0; i < records; ++i) {
        name_offset = *offset;
        mdns_string_skip(buffer, size, offset);
        if (((*offset) + 10) > size)
            return parsed;
        name_length = (*offset) - name_offset;
        data = (const uint16_t *)MDNS_POINTER_OFFSET(buffer, *offset);

        rtype = mdns_ntohs(data++);
        rclass = mdns_ntohs(data++);
        ttl = mdns_ntohl(data);
        data += 2;
        length = mdns_ntohs(data++);

        *offset += 10;

        if (length <= (size - (*offset))) {
            ++parsed;
            if (callback && callback(sock, from, addrlen, type, query_id, rtype, rclass, ttl, buffer, size, name_offset,
                                     name_length, *offset, length, user_data))
                break;
        }

        *offset += length;
    }
    return parsed;
}

static inline int mdns_unicast_send(int sock, const void *address, size_t address_size, const void *buffer,
                                    size_t size) {
    if (sendto(sock, (const char *)buffer, (mdns_size_t)size, 0, (const struct sockaddr *)address,
               (socklen_t)address_size) < 0) {
        MY_ERROR("send dns query packet failed: %d, %s", errno, strerror(errno));
        return -1;
    }
    return 0;
}

static inline int mdns_query_send(int sock, const void *saddr, size_t saddrlen, mdns_record_type_t type,
                                  const char *name, void *buffer, size_t capacity, uint16_t query_id) {
    mdns_query_t query = {0};
    query.type = type;
    query.name = name;
    query.length = strlen(name);
    return mdns_multiquery_send(sock, saddr, saddrlen, &query, 1, buffer, capacity, query_id);
}

static inline int mdns_multiquery_send(int sock, const void *saddr, size_t saddrlen, const mdns_query_t *query,
                                       size_t count, void *buffer, size_t capacity, uint16_t query_id) {
    uint16_t rclass = MDNS_CLASS_IN;
    struct mdns_header_t *header = NULL;

    size_t iq = 0, tosend = 0, remain = 0;
    void *data = NULL;

    if (!count || (capacity < (sizeof(struct mdns_header_t) + (6 * count)))) {
        return -1;
    }

    header = (struct mdns_header_t *)buffer;
    // Query ID
    header->query_id = htons((unsigned short)query_id);
    // Flags
    header->flags = htons(0x0100); // recursion desired
    // Questions
    header->questions = htons((unsigned short)count);
    // No answer, authority or additional RRs
    header->answer_rrs = 0;
    header->authority_rrs = 0;
    header->additional_rrs = 0;
    // Fill in questions
    data = MDNS_POINTER_OFFSET(buffer, sizeof(struct mdns_header_t));
    for (iq = 0; iq < count; ++iq) {
        // Name string
        data = mdns_string_make(buffer, capacity, data, query[iq].name, query[iq].length, 0);
        if (!data) {
            MY_ERROR("Failed to encode query name string!");
            return -1;
        }
        remain = capacity - MDNS_POINTER_DIFF(data, buffer);
        if (remain < 4) {
            MY_WARN("No enouth free space!");
            return -1;
        }
        // Record type
        data = mdns_htons(data, query[iq].type);
        //! Optional unicast response based on local port, class IN
        data = mdns_htons(data, rclass);
    }

    tosend = MDNS_POINTER_DIFF(data, buffer);
    if (mdns_unicast_send(sock, saddr, saddrlen, buffer, tosend)) {
        MY_ERROR("Failed to send dns query!");
        return -1;
    }
    return query_id;
}

static inline size_t mdns_query_recv(int sock, void *buffer, size_t capacity, mdns_record_callback_fn callback,
                                     void *user_data, int only_query_id) {
    struct sockaddr_in6 addr = {0};
    struct sockaddr *saddr = (struct sockaddr *)&addr;
    socklen_t addrlen = sizeof(addr);
    const uint16_t *data = NULL;
    size_t data_size = 0;
    size_t records = 0, total_records = 0, offset = 0;
    uint16_t query_id = 0, flags = 0, questions = 0;
    uint16_t answer_rrs = 0, authority_rrs = 0, additional_rrs = 0;
    mdns_ssize_t ret = 0;
    int i = 0;

#ifdef __APPLE__
    saddr->sa_len = sizeof(addr);
#endif
    ret = recvfrom(sock, (char *)buffer, (mdns_size_t)capacity, 0, saddr, &addrlen);
    if (ret <= 0) {
        return 0;
    }

    data_size = (size_t)ret;
    data = (const uint16_t *)buffer;

    query_id = mdns_ntohs(data++);
    flags = mdns_ntohs(data++);
    questions = mdns_ntohs(data++);
    answer_rrs = mdns_ntohs(data++);
    authority_rrs = mdns_ntohs(data++);
    additional_rrs = mdns_ntohs(data++);
    (void)sizeof(flags);

    if ((only_query_id > 0) && (query_id != only_query_id)) {
        // Not a reply to the wanted one-shot query
        return 0;
    }
    // Skip questions part
    for (i = 0; i < questions; ++i) {
        offset = MDNS_POINTER_DIFF(data, buffer);
        if (!mdns_string_skip(buffer, data_size, &offset))
            return 0;
        data = (const uint16_t *)MDNS_POINTER_OFFSET_CONST(buffer, offset);
        // Record type and class not used, skip
        // uint16_t rtype = mdns_ntohs(data++);
        // uint16_t rclass = mdns_ntohs(data++);
        data += 2;
    }

    records = 0;
    total_records = 0;
    offset = MDNS_POINTER_DIFF(data, buffer);
    records = mdns_records_parse(sock, saddr, addrlen, buffer, data_size, &offset, MDNS_ENTRYTYPE_ANSWER, query_id,
                                 answer_rrs, callback, user_data);
    total_records += records;
    if (records != answer_rrs) {
        return total_records;
    }

    records = mdns_records_parse(sock, saddr, addrlen, buffer, data_size, &offset, MDNS_ENTRYTYPE_AUTHORITY, query_id,
                                 authority_rrs, callback, user_data);
    total_records += records;
    if (records != authority_rrs) {
        return total_records;
    }

    records = mdns_records_parse(sock, saddr, addrlen, buffer, data_size, &offset, MDNS_ENTRYTYPE_ADDITIONAL, query_id,
                                 additional_rrs, callback, user_data);
    total_records += records;
    if (records != additional_rrs) {
        return total_records;
    }

    return total_records;
}

static inline mdns_string_t mdns_record_parse_ptr(const void *buffer, size_t size, size_t offset, size_t length,
                                                  char *strbuffer, size_t capacity) {
    // PTR record is just a string
    if ((size >= offset + length) && (length >= 2))
        return mdns_string_extract(buffer, size, &offset, strbuffer, capacity);
    mdns_string_t empty = {0, 0};
    return empty;
}

static inline mdns_record_srv_t mdns_record_parse_srv(const void *buffer, size_t size, size_t offset, size_t length,
                                                      char *strbuffer, size_t capacity) {
    mdns_record_srv_t srv;
    memset(&srv, 0, sizeof(mdns_record_srv_t));
    // Read the service priority, weight, port number and the discovery name
    // SRV record format (http://www.ietf.org/rfc/rfc2782.txt):
    // 2 bytes network-order unsigned priority
    // 2 bytes network-order unsigned weight
    // 2 bytes network-order unsigned port
    // string: discovery (domain) name, minimum 2 bytes when compressed
    if ((size >= offset + length) && (length >= 8)) {
        const uint16_t *recorddata = (const uint16_t *)MDNS_POINTER_OFFSET_CONST(buffer, offset);
        srv.priority = mdns_ntohs(recorddata++);
        srv.weight = mdns_ntohs(recorddata++);
        srv.port = mdns_ntohs(recorddata++);
        offset += 6;
        srv.name = mdns_string_extract(buffer, size, &offset, strbuffer, capacity);
    }
    return srv;
}

static inline struct sockaddr_in *mdns_record_parse_a(const void *buffer, size_t size, size_t offset, size_t length,
                                                      struct sockaddr_in *addr) {
    memset(addr, 0, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
#ifdef __APPLE__
    addr->sin_len = sizeof(struct sockaddr_in);
#endif
    if ((size >= offset + length) && (length == 4))
        memcpy(&addr->sin_addr.s_addr, MDNS_POINTER_OFFSET(buffer, offset), 4);
    return addr;
}

static inline struct sockaddr_in6 *mdns_record_parse_aaaa(const void *buffer, size_t size, size_t offset, size_t length,
                                                          struct sockaddr_in6 *addr) {
    memset(addr, 0, sizeof(struct sockaddr_in6));
    addr->sin6_family = AF_INET6;
#ifdef __APPLE__
    addr->sin6_len = sizeof(struct sockaddr_in6);
#endif
    if ((size >= offset + length) && (length == 16))
        memcpy(&addr->sin6_addr, MDNS_POINTER_OFFSET(buffer, offset), 16);
    return addr;
}

static inline size_t mdns_record_parse_txt(const void *buffer, size_t size, size_t offset, size_t length,
                                           mdns_record_txt_t *records, size_t capacity) {
    size_t parsed = 0;
    const char *strdata;
    size_t end = offset + length;

    if (size < end)
        end = size;

    while ((offset < end) && (parsed < capacity)) {
        strdata = (const char *)MDNS_POINTER_OFFSET(buffer, offset);
        size_t sublength = *(const unsigned char *)strdata;

        if (sublength >= (end - offset))
            break;

        ++strdata;
        offset += sublength + 1;

        size_t separator = sublength;
        for (size_t c = 0; c < sublength; ++c) {
            // DNS-SD TXT record keys MUST be printable US-ASCII, [0x20, 0x7E]
            if ((strdata[c] < 0x20) || (strdata[c] > 0x7E)) {
                separator = 0;
                break;
            }
            if (strdata[c] == '=') {
                separator = c;
                break;
            }
        }

        if (!separator)
            continue;

        if (separator < sublength) {
            records[parsed].key.str = strdata;
            records[parsed].key.length = separator;
            records[parsed].value.str = strdata + separator + 1;
            records[parsed].value.length = sublength - (separator + 1);
        } else {
            records[parsed].key.str = strdata;
            records[parsed].key.length = sublength;
            records[parsed].value.str = 0;
            records[parsed].value.length = 0;
        }

        ++parsed;
    }

    return parsed;
}

#ifdef _WIN32
#undef strncasecmp
#endif

#ifdef __cplusplus
}
#endif

#endif