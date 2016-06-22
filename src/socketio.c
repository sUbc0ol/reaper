/* todo bsd vs. linux */
#include "socketio.h"
#include "protocol.h"
#include "util.h"

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
struct bpf_insn rpr_bpf_code[] = {
    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 0, 3, 0x00000800 },
    { 0x30, 0, 0, 0x00000017 },
    { 0x15, 0, 1, IPPROTO_RPR }, //ip protocol 182
    { 0x6, 0, 0, 0x00040000 },
    { 0x6, 0, 0, 0x00000000 }
};

int set_bpf_options(int fd, char *iface)
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

/* fill out rpr_socket with interface and pass it in here
 * Returns 0 on success, -1 on error
 */
int rpr_init_socket(struct rpr_socket* rprsock){
    char bpfdev[12];
    struct bpf_program bpfilter;
    for (int i=0;i<256;++i){
        snprintf(bpfdev, 11, "/dev/bpf%d", i);
        if ((rprsock->fd = open(bpfdev, O_RDWR)) > 0)
            break;
        if (rprsock->fd == 255)
            return -1;
    }
    
    if (set_bpf_options(rprsock->fd, rprsock->iface) < 0){
        perror("rpr_init_socket set_bpf_options");
        close(rprsock->fd);
        return -1;
    }

    if (ioctl(rprsock->fd, BIOCGBLEN, &(rprsock->blen)) < 0){
        perror("rpr_init_socket BIOCGBLEN");
        close(rprsock->fd);
        return -1;
    }

    bpfilter.bf_len = 6;
    bpfilter.bf_insns = (struct bpf_insn*)rpr_bpf_code;
    if (ioctl(rprsock->fd, BIOCSETF, &bpfilter) < 0){
        perror("rpr_init_socket BIOCSETF");
        close(rprsock->fd);
        return -1;
    }

    return 0;
}

//return the length of the ethernet frame in buf. caller is responsible for freeing buf
int rpr_get_frame(struct rpr_socket* rprsock, u_char **buf){
    int nread;
    if ((*buf = (u_char*)calloc(1, rprsock->blen)) < 0){
        perror("rpr_recv malloc failed");
        exit(1);
    }
    /* TODO: implement timeouts using select */
    if ((nread = read(rprsock->fd, *buf, rprsock->blen)) < 0)
        return nread;

    //put ethernet header in buf
    struct bpf_hdr *bhdr = (struct bpf_hdr*)(*buf);
    u_char *frame_buf = (u_char*)calloc(1, bhdr->bh_datalen);
    memcpy((u_char*)frame_buf, (*buf + bhdr->bh_hdrlen), bhdr->bh_datalen);
    free(*buf);
    *buf = frame_buf;
    return bhdr->bh_datalen;
}

#endif

#if defined(__linux__)
#endif


// change to use rpr get frame
int rpr_recv(struct rpr_socket* rprsock, u_char *buf, int len){
    struct ether_header *frame_buf = NULL;
    int nread;
    if ((nread = rpr_get_frame(rprsock, (u_char**)&frame_buf)) < 0){
        free(frame_buf);
        return -1;
    }

    struct ip *iph = get_iph((u_char*)frame_buf);
    struct reaper_dgram_hdr *rprdgrm = (struct reaper_dgram_hdr*)get_udph((u_char*)frame_buf);
    free(frame_buf);
    return nread;
}
