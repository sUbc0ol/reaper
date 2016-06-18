#ifndef REAPER_PROTOCOL_H_
#define REAPER_PROTOCOL_H_
#include <netinet/udp.h>
#include <sys/types.h>


// Remote Extensible Admininstration Protocol, Extra Reliable
/* reaper protocol header spec
 * 0        9       17      25    31
 * ---------------------------------
 * |ver/type| flags |  client ID   |
 * |_______________________________|
 * |       Sequence Number         |
 * |_______________________________|
 * |    Acknowledgement Number     |
 * |_______________________________|
 */

struct __attribute__((packed)) reaper_header {
#if BYTE_ORDER == LITTLE_ENDIAN
	u_int	  type:24,
		  version:4;
#endif
#if BYTE_ORDER == BIG_ENDIAN
	u_int	  version:4,
		  type:24;
#endif
        u_char    flags;
#define	RH_FIN	  0x01 /* finished transaction, no more parts to receive */
#define	RH_ACK    0x02 /* acknowledgement */
#define	RH_NAK	  0x04 /* do not acknowledge */
#define	RH_R1	  0x08 /* reserved 1 */
#define	RH_R2	  0x10 /* reserved 2 */
#define	RH_R3	  0x20 /* reserved 3 */
#define	RH_R4	  0x40 /* reserved 4 */
#define	RH_R5	  0x80 /* reserved 5 */
        u_short   client_id;
        u_int32_t seq;
        u_int32_t ack;
};

struct __attribute__((packed)) reaper_dgram_hdr {
    struct udphdr        *uhdr;
    struct reaper_header *r_hdr;
};

#define IPPROTO_RPR 0xb6 
#endif
