/* todo bsd vs. linux */
#include "socketio.h"

struct bpf_insn rpr_bpf_code[] = {
    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 0, 3, 0x00000800 },
    { 0x30, 0, 0, 0x00000017 },
    { 0x15, 0, 1, 0x000000b6 }, //ip protocol 182
    { 0x6, 0, 0, 0x00040000 },
    { 0x6, 0, 0, 0x00000000 }
};

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
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

#endif

#if defined(__linux__)
#endif
