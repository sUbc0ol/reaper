#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/ndrv.h>
#include <string.h>
#include <unistd.h>

#define ZeroMem(a,b) memset(&a, 0, b)
#define ZeroType(a,b) memset(&a, 0, sizeof(b))

int main(int argc, char *argv[])
{
    int fd;
    char buf[2048];
    struct sockaddr_ndrv ndrv;
    struct ndrv_protocol_desc protodesc;
    //struct ndrv_demux_desc demuxdesc;
    struct ndrv_demux_desc demuxdesc[1];
    ZeroType(ndrv, struct sockaddr_ndrv);
    ZeroType(protodesc, struct ndrv_protocol_desc);
    ZeroType((demuxdesc[0]), struct ndrv_demux_desc);
    if ((fd = socket(PF_NDRV, SOCK_RAW, 0)) < 0){
        perror("socket");
        return 1;
    }

    int yes = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
        perror("setsockopt SO_REUSEADDR");
        close(fd);
        return 1;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(int)) == -1) {
        perror("setsockopt SO_REUSEPORT");
        close(fd);
        return 1;
    }

    ndrv.snd_len = sizeof(ndrv);
    strncpy((char*)ndrv.snd_name, "en0", IFNAMSIZ);
    ndrv.snd_family = AF_NDRV;
    if (bind(fd, (struct sockaddr*)&ndrv, sizeof(ndrv)) > 0){
        perror("bind");
        close(fd);
        return 1;
    }

    protodesc.version = NDRV_PROTOCOL_DESC_VERS;
    protodesc.protocol_family = (u_int32_t)12346;
    protodesc.demux_count = 1;
    protodesc.demux_list = demuxdesc;
    demuxdesc[0].type = NDRV_DEMUXTYPE_ETHERTYPE;
    demuxdesc[0].length = sizeof(unsigned short);
    demuxdesc[0].data.ether_type = htons(0x0800);

    if (setsockopt(fd, SOL_NDRVPROTO, NDRV_SETDMXSPEC, (caddr_t)&protodesc, sizeof(protodesc))){
        perror("setsockopt SOL_NDRVPROTO SET");
        close(fd);
        return 1;
    }
    recvfrom(fd, buf, 2048, 0, NULL, NULL);

    return 0;
}
