#include "socketio.h"
#include "protocol.h"

int main(int argc, char *argv[])
{
    u_char *recvbuf = NULL;
    struct rpr_socket rprsock;
    int nread;
    rprsock.iface = "en0";
    rpr_init_socket(&rprsock);
    nread = rpr_recv(&rprsock, recvbuf, 1072);
    write(1, recvbuf, nread);
    free(recvbuf);
    return 0;
}
