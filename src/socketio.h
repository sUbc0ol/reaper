/* todo bsd vs. linux */
#ifndef REAPER_SOCKETIO_H_
#define REAPER_SOCKETIO_H_

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
#include <string.h>
#include <arpa/inet.h>

struct rpr_socket {
    int fd;
    int blen;
    char *iface;
};

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <net/bpf.h>

int rpr_init_socket(struct rpr_socket *);
#endif

#endif //ifndef REAPER_SOCKETIO_H_
