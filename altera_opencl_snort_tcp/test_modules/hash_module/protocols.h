#ifndef PROTOCOLS_H
#define PROTOCOLS_H

/*++ ethernet header details ++*/

#define ETH_ADDR_LEN 6
#define ETH_HDR_LEN 14

#define ETH_TYPE_IPV4 	0x0800

#define ETH_DST_OFFSET	0
#define ETH_DST_SIZE	ETH_ADDR_LEN
#define ETH_SRC_OFFSET	ETH_DST_OFFSET+ETH_DST_SIZE
#define ETH_SRC_SIZE	ETH_ADDR_LEN
#define ETH_TYPE_OFFSET ETH_SRC_OFFSET+ETH_SRC_SIZE
#define ETH_TYPE_SIZE	2

typedef struct {
	uint8_t		eth_dst[ETH_ADDR_LEN];	/* destination address */
	uint8_t		eth_src[ETH_ADDR_LEN];	/* source address */
	uint16_t	eth_type;				/* payload type */
} eth_hdr_struct;

/*-- ethernet header details --*/

/*++ ipv4 header details ++*/

#define IPV4_HDR_LEN 20
#define IPV4_ADDR_LEN 4

#define	IPV4_PROTO_TCP		6		/* TCP */
#define	IPV4_PROTO_UDP		17		/* UDP */

#define IPV4_V_HL_OFFSET		0
#define IPV4_V_HL_SIZE			1
#define IPV4_TOS_OFFSET			IPV4_V_HL_OFFSET+IPV4_V_HL_SIZE
#define IPV4_TOS_SIZE			1
#define IPV4_LEN_OFFSET			IPV4_TOS_OFFSET+IPV4_TOS_SIZE
#define IPV4_LEN_SIZE	 		2
#define IPV4_ID_OFFSET			IPV4_LEN_OFFSET+IPV4_LEN_SIZE
#define IPV4_ID_SIZE			2
#define IPV4_OFF_OFFSET			IPV4_ID_OFFSET+IPV4_ID_SIZE
#define IPV4_OFF_SIZE			2
#define IPV4_TTL_OFFSET			IPV4_OFF_OFFSET+IPV4_OFF_SIZE
#define IPV4_TTL_SIZE			1
#define IPV4_PROTO_OFFSET		IPV4_TTL_OFFSET+IPV4_TTL_SIZE
#define IPV4_PROTO_SIZE			1
#define IPV4_SUM_OFFSET			IPV4_PROTO_OFFSET+IPV4_PROTO_SIZE
#define IPV4_SUM_SIZE			2
#define IPV4_SRC_OFFSET			IPV4_SUM_OFFSET+IPV4_SUM_SIZE
#define IPV4_SRC_SIZE			4
#define IPV4_DST_OFFSET			IPV4_SRC_OFFSET+IPV4_SRC_SIZE
#define IPV4_DST_SIZE			4

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

/*-- ipv4 header details --*/

/* ++ tcp header details ++*/
#define TCP_HDR_LEN		20

#define TCP_SRC_PORT_OFFSET		0
#define TCP_SRC_PORT_SIZE		2
#define TCP_DST_PORT_OFFSET		TCP_SRC_PORT_OFFSET+TCP_SRC_PORT_SIZE
#define TCP_DST_PORT_SIZE		2
#define TCP_SEQ_OFFSET			TCP_DST_PORT_OFFSET+TCP_DST_PORT_SIZE
#define TCP_SEQ_SIZE			4
#define TCP_ACK_OFFSET			TCP_SEQ_OFFSET+TCP_SEQ_SIZE
#define TCP_ACK_SIZE			4
#define TCP_OFF_OFFSET			TCP_ACK_OFFSET+TCP_ACK_SIZE
#define TCP_OFF_SIZE			1
#define TCP_FLAGS_OFFSET		TCP_OFF_OFFSET+TCP_OFF_SIZE
#define TCP_FLAGS_SIZE			1
#define TCP_WIN_OFFSET			TCP_FLAGS_OFFSET+TCP_FLAGS_SIZE
#define TCP_PARSER_WIN_SIZE		2
#define TCP_SUM_OFFSET			TCP_WIN_OFFSET+TCP_PARSER_WIN_SIZE
#define TCP_SUM_SIZE			2
#define TCP_URP_OFFSET			TCP_SUM_OFFSET+TCP_SUM_SIZE
#define TCP_URP_SIZE			2

#define TCP_HDR_LEN_OFFSET		12
#define TCP_PORT_HTTP 80
/*-- tcp header details --*/

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

/*-- tcp header details --*/

#define HTTP_DATA_MAX_SIZE 1480	//div by 8

#define PARSER_PARSER_WIN_SIZE PARSER_WIN_SIZE
#define ETH_HDR_LEN_OFFSET_WIN 	(ETH_HDR_LEN%PARSER_PARSER_WIN_SIZE)
#define IPV4_HDR_LEN_OFFSET_WIN (ETH_HDR_LEN+IPV4_HDR_LEN)%PARSER_PARSER_WIN_SIZE
#define TCP_HDR_LEN_OFFSET_WIN 	(ETH_HDR_LEN+IPV4_HDR_LEN+TCP_HDR_LEN)%PARSER_PARSER_WIN_SIZE

#endif
