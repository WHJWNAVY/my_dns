
#ifndef __MY_DEBUG__
#define __MY_DEBUG__

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// #define MY_DEBUG_FILE "/var/log/my_debug.log"

#define MY_DEBUG_TO_FILE(file, ...)                             \
    do {                                                        \
        FILE *__MY_DBG_FD__ = fopen(file, "a+");                \
        if (__MY_DBG_FD__ == NULL)                              \
            __MY_DBG_FD__ = stderr;                             \
        fprintf(__MY_DBG_FD__, __VA_ARGS__);                    \
        fprintf(__MY_DBG_FD__, "\n");                           \
        if (__MY_DBG_FD__ != stderr)                            \
            fclose(__MY_DBG_FD__);                              \
    } while (0)

#define MY_DEBUG2(...)                                \
    do {                                              \
        MY_DEBUG_TO_FILE(MY_DEBUG_FILE, __VA_ARGS__); \
    } while (0)

#define LOGL_DEBUG "DEBUG"
#define LOGL_INFO "INFO"
#define LOGL_WARNING "WARNING"
#define LOGL_ERROR "ERROR"

#ifdef MY_DEBUG_FILE
#define MY_LOG(LEVEL, FMT, ...)                                                          \
    do {                                                                                 \
        MY_DEBUG2(">>>>>> (%s:%d) <%s> " FMT, __func__, __LINE__, LEVEL, ##__VA_ARGS__); \
    } while (0)
#else
#define MY_LOG(LEVEL, FMT, ...)                                                                     \
    do {                                                                                            \
        fprintf(stderr, ">>>>>> (%s:%d) <%s> " FMT "\n", __func__, __LINE__, LEVEL, ##__VA_ARGS__); \
    } while (0)
#endif

#if DEBUG_LEVEL > 0
#warning "Debug Mode!!!"
#define MY_DEBUG(FMT, ...) MY_LOG(LOGL_DEBUG, FMT, ##__VA_ARGS__)
#else
#warning "Release Mode!!!"
#define MY_DEBUG(FMT, ...)
#endif

#define MY_INFO(FMT, ...) MY_LOG(LOGL_INFO, FMT, ##__VA_ARGS__)
#define MY_WARN(FMT, ...) MY_LOG(LOGL_WARNING, FMT, ##__VA_ARGS__)
#define MY_ERROR(FMT, ...) MY_LOG(LOGL_ERROR, FMT, ##__VA_ARGS__)

#define ARRAY_LEN(array, type) (sizeof(array) / sizeof(type))

#define MY_DEBUG_HEX(hex_array, hex_len)                                                     \
    do {                                                                                     \
        fprintf(stderr, "===[%ld]=== %s(%s:%d) ", time(NULL), __func__, __FILE__, __LINE__); \
        if (((hex_array) != NULL) && (hex_len > 0)) {                                        \
            fprintf(stderr, "hex[%p], len[%d]", (hex_array), (hex_len));                     \
            uint8_t *__p_array___ = (uint8_t *)(hex_array);                                  \
            for (uint32_t __i__ = 0; __i__ < (hex_len); __i__++) {                           \
                fprintf(stderr, "%s", ((__i__ % 16 == 0) ? "\r\n" : ""));                    \
                fprintf(stderr, "%02X ", (__p_array___)[__i__]);                             \
            }                                                                                \
        } else {                                                                             \
            fprintf(stderr, "hex %s NULL, len %s 0", (((hex_array) == NULL) ? "==" : "!="),  \
                    (((hex_len) == 0) ? "==" : "!="));                                       \
        }                                                                                    \
        fprintf(stderr, "\r\n");                                                             \
    } while (0)

#endif