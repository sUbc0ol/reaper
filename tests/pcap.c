#define _IP_VHL
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <string.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/tcpip.h>
#include <net/ethernet.h>

#define ZeroMem(a,b) memset(&a, 0, b)
#define ZeroType(a,b) memset(&a, 0, sizeof(b))
#define pperror() fprintf(stderr, "PCAP ERROR: %s", errbuf);

void handlepacket(u_char *, const struct pcap_pkthdr *, const u_char *);

int main(int argc, char *argv[])
{
    char recvbuf[2048], *dev, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        pperror();
        return 1;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
	pperror();
	return 1;
    }

    pcap_loop(handle, -1, (pcap_handler)handlepacket, NULL);
    
    pcap_close(handle);


    return 0;
}

void handlepacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
        struct tcphdr *tcph;
        struct ether_header *ehdr;
        struct ip *iph;
        ehdr = (struct ether_header*)packet;
        if (ehdr->ether_type != htons(ETHERTYPE_IP)) return;
        iph = (struct ip*)packet + ETHER_HDR_LEN;
        printf("%d\n", IP_VHL_HL(iph->ip_vhl));
        tcph = (struct tcphdr*)packet + ETHER_HDR_LEN + IP_VHL_HL(iph->ip_vhl) * 4;
        printf("spt: %d, dpt: %d\n", tcph->th_sport, tcph->th_dport);
}
