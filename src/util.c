#include "util.h"
#include <stdio.h>
#include <sys/socket.h>

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
struct ether_header *get_eh(u_char *bpfh){
    return (struct ether_header*)(bpfh + ((struct bpf_hdr*)bpfh)->bh_hdrlen);
}
#endif

struct ip *get_iph(u_char *ehdr){
    return (struct ip*)(ehdr + ETHER_HDR_LEN);
}

struct udphdr *get_udph(u_char *ehdr){
    struct ip *iph;
    iph = get_iph(ehdr);
    return (struct udphdr*)((u_char*)iph + (iph->ip_hl*4));
}

void dump_reaper_hdr(struct reaper_header hdr){
    printf("version: %d\ntype: %d\nflags: %d\nclient_id: %hu\nseq: %d\n ack: %d\n", hdr.version, hdr.type, hdr.flags, ntohs(hdr.client_id), ntohl(hdr.seq), ntohl(hdr.ack));
}
