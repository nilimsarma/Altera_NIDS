`ifndef PROTOCOLS_TYPEDEFS_SV
`define PROTOCOLS_TYPEDEFS_SV

`include "generic/protocols.vh"
package PROTOCOLS_TYPEDEFS_P;
import TYPEDEFS_P::*;

typedef struct {
	uint8_t		eth_dst[`ETH_ADDR_LEN];	/* destination address */
	uint8_t		eth_src[`ETH_ADDR_LEN];	/* source address */
	uint16_t	eth_type;				/* payload type */
} eth_hdr_struct;

typedef struct  {
	
	//little endian
	uint8_t		ip_v;		/* version */
	uint8_t		ip_hl;		/* header length (incl any options) */
	uint8_t		ip_tos;		/* type of service */
	uint16_t	ip_len;		/* total length (incl header) */
	uint16_t	ip_id;		/* identification */
	uint16_t	ip_off;		/* fragment offset and flags */
	uint8_t		ip_ttl;		/* time to live */
	uint8_t		ip_p;		/* protocol */
	uint16_t	ip_sum;		/* checksum */
	uint32_t	ip_src;		/* source address */
	uint32_t	ip_dst;		/* destination address */
} ipv4_hdr_struct;

//TCP header, without options
typedef struct {
	uint16_t	th_sport;	/* source port */
	uint16_t	th_dport;	/* destination port */
	uint32_t	th_seq;		/* sequence number */
	uint32_t	th_ack;		/* acknowledgment number */
	uint8_t		th_off;		/* data offset */
	uint8_t		th_x2;		/* (unused) */
	uint8_t		th_flags;	/* control flags */
	uint16_t	th_win;		/* window */
	uint16_t	th_sum;		/* checksum */
	uint16_t	th_urp;		/* urgent pointer */
} tcp_hdr_struct;

endpackage

`endif