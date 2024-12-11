#ifndef __GNUC__
#ifndef _GETOPT_H
#define _GETOPT_H

#ifdef __cplusplus
extern "C" {
#endif

#define optreset __optreset

int getopt(int, char * const [], const char *);
extern char *optarg;
extern int optind, opterr, optopt, optreset;

struct option {
	const char *name;
	int has_arg;
	int *flag;
	int val;
};

void __getopt_msg(const char* a, const char* b, const char* c, size_t l);
int getopt_long(int, char *const *, const char *, const struct option *, int *);
int getopt_long_only(int, char *const *, const char *, const struct option *, int *);

#define no_argument        0
#define required_argument  1
#define optional_argument  2

#ifdef __cplusplus
}
#endif

#endif
#else
#include <getopt.h>
#endif