#ifndef REAPER_UTIL_H_
#define REAPER_UTIL_H_
#include <net/ethernet.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include "protocol.h"

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <net/bpf.h>
struct ether_header *get_eh(u_char *bpfh);
#endif

struct ip *get_iph(u_char *ehdr);
struct udphdr *get_udph(u_char *ehdr);
void dump_reaper_hdr(struct reaper_header hdr);

#endif
