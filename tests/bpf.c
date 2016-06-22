#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <string.h>
#include <arpa/inet.h>

struct ether_header *get_eh(u_char *bpfh){
    return (struct ether_header*)(bpfh + ((struct bpf_hdr*)bpfh)->bh_hdrlen);
}

struct ip *get_iph(u_char *ehdr){
    return (struct ip*)(ehdr + ETHER_HDR_LEN);
}

struct tcphdr *get_tcph(u_char *ehdr){
    struct ip *iph;
    iph = get_iph(ehdr);
    return (struct tcphdr*)((u_char*)iph + (iph->ip_hl*4));
}

//https://gist.github.com/msantos/939154
int set_options(int fd, char *iface)
{
    struct ifreq ifr;
    u_int32_t enable = 1;


    /* Associate the bpf device with an interface */
    (void)strlcpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name)-1);

    if(ioctl(fd, BIOCSETIF, &ifr) < 0)
        return -1;

    /* Set header complete mode */
    if(ioctl(fd, BIOCSHDRCMPLT, &enable) < 0)
        return -1;

    /* Monitor packets sent from our interface */
    if(ioctl(fd, BIOCSSEESENT, &enable) < 0)
        return -1;

    /* Return immediately when a packet received */
    if(ioctl(fd, BIOCIMMEDIATE, &enable) < 0)
        return -1;

    return 0;
}

int main(int argc, char *argv[])
{
    int fd;
    char device[12];
    int blen;
    u_char *buf;
    int i;
    char iface[4];

    struct bpf_hdr* bhdr;
    struct ether_header *ehdr;
    struct ip *iph;
    struct tcphdr *th;

    for (i=0;i<256;++i){
        snprintf(device, 11, "/dev/bpf%d", i);
        if ((fd = open(device, O_RDONLY)) > 0)
            break;
        if (fd == 255)
            return 1;
    }

    strcpy(iface, "en0");
    set_options(fd, iface);

    if (ioctl(fd, BIOCGBLEN, &blen) < 0){
        perror("ioctl");
        close(fd);
        return 0;
    }
    buf = (u_char*)calloc(1, blen);

    for (i=0; i<256; ++i){
        read(fd, buf, blen);
        bhdr = (struct bpf_hdr*)buf;
        ehdr = get_eh(buf);
        if (ehdr->ether_type == htons(ETHERTYPE_IP)){
            iph = get_iph((u_char*)ehdr);
            printf("src: %s, dst: %s", inet_ntoa(iph->ip_src), inet_ntoa(iph->ip_dst));
            if (iph->ip_p == IPPROTO_TCP){
                th = get_tcph((u_char*)ehdr);
                printf(" ---- spt: %hu, dpt: %hu", ntohs(th->th_sport), ntohs(th->th_dport));
            }
            printf("\n");
        }
    }

    free(buf);
    close(fd);

    return 0;
}
