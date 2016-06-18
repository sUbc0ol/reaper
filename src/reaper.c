#include "socketio.h"
#include "protocol.h"

int main(int argc, char *argv[])
{
    struct rpr_socket rprsock;
    rprsock.iface = "en0";
    rpr_init_socket(&rprsock);
    return 0;
}
