#ifndef PARSER_H
#define PARSER_H

#define PARSER_WIN_SIZE 4

typedef struct {
	uint8_t data[PARSER_WIN_SIZE];
} data_stream_t;

typedef enum
{
	ETH = 0,
	IPV4,
	TCP,
	UDP,
	HTTP,
	TCP_INSPECT,
	TCP_SEGMENT,
	TCP_PAYLOAD,
	NUM_PROTOCOLS
	
}data_stream_ch_t;


typedef enum
{
	HEADER_START,				//start header extraction
	HEADER_CONT,				//continue header extraction
	HEADER_END_PAYLOAD, 		//end header extraction, start payload extraction
	HEADER_END,					//end header extraction, payload or variable options starts in next window
	HEADER_END_OPTIONS,			//end header extraction, variable options etc starts which we donot parse
	HEADER_OPTIONS_CONT,		//pass over header options
	HEADER_OPTIONS_END_PAYLOAD, //variable options end, payload starts
	PAYLOAD,					//extract payload
	UNKNOWN,					//unknown data, wait till end of packet
	PARSER_DONE
} parse_state;

typedef enum
{
	state_pass_thru,
	state_write_pkt,
	state_read_pkt,
	state_none
	
} tcp_inspect_state_t;


void parse_eth_header(uint8_t* eth_hdr_arr, eth_hdr_struct* eth_hdr)
{
	uint8_t i,j;
	
	#pragma unroll
	for(i=ETH_DST_OFFSET, j=0; j<ETH_DST_SIZE; i++, j++)	eth_hdr->eth_dst[j] = eth_hdr_arr[i];
	
	#pragma unroll
	for(i=ETH_SRC_OFFSET, j=0; j<ETH_SRC_SIZE; i++, j++)	eth_hdr->eth_src[j] = eth_hdr_arr[i];
	
	eth_hdr->eth_type = (eth_hdr_arr[ETH_TYPE_OFFSET]<<8)|(eth_hdr_arr[ETH_TYPE_OFFSET+1]);
}


void parse_ipv4_header(uint8_t* ipv4_hdr_arr, ipv4_hdr_struct* ipv4_hdr)
{
	//fill struct
	ipv4_hdr->ip_v = 	(ipv4_hdr_arr[IPV4_V_HL_OFFSET] & 0xF0)>>4;	//bits 7-4
	ipv4_hdr->ip_hl = 	ipv4_hdr_arr[IPV4_V_HL_OFFSET] & 0x0F;		//bits 3-0
	ipv4_hdr->ip_tos = 	ipv4_hdr_arr[IPV4_TOS_OFFSET];
	ipv4_hdr->ip_len = 	(ipv4_hdr_arr[IPV4_LEN_OFFSET]<<8) | (ipv4_hdr_arr[IPV4_LEN_OFFSET+1]); //ntoh
	ipv4_hdr->ip_id = 	(ipv4_hdr_arr[IPV4_ID_OFFSET]<<8)  | (ipv4_hdr_arr[IPV4_ID_OFFSET+1]);	//ntoh
	ipv4_hdr->ip_off = 	(ipv4_hdr_arr[IPV4_OFF_OFFSET]<<8) | (ipv4_hdr_arr[IPV4_OFF_OFFSET+1]);	//ntoh
	ipv4_hdr->ip_ttl = 	ipv4_hdr_arr[IPV4_TTL_OFFSET];
	ipv4_hdr->ip_p = 	ipv4_hdr_arr[IPV4_PROTO_OFFSET];
	ipv4_hdr->ip_sum = 	(ipv4_hdr_arr[IPV4_SUM_OFFSET]<<8) | (ipv4_hdr_arr[IPV4_SUM_OFFSET+1]); //ntoh
	
	ipv4_hdr->ip_src = ipv4_hdr_arr[IPV4_SRC_OFFSET]&0xFF;
	#pragma unroll
	for(uint8_t i=1; i<IPV4_SRC_SIZE; i++)
	ipv4_hdr->ip_src = 	((ipv4_hdr->ip_src)<<8) | ipv4_hdr_arr[IPV4_SRC_OFFSET+i];

	ipv4_hdr->ip_dst = ipv4_hdr_arr[IPV4_DST_OFFSET]&0xFF;
	#pragma unroll
	for(uint8_t i=1; i<IPV4_DST_SIZE; i++)
	ipv4_hdr->ip_dst = 	((ipv4_hdr->ip_dst)<<8) | ipv4_hdr_arr[IPV4_DST_OFFSET+i];
	
}

void parse_tcp_header(uint8_t* tcp_hdr_arr, tcp_hdr_struct* tcp_hdr)
{
	tcp_hdr->th_sport =	(tcp_hdr_arr[TCP_SRC_PORT_OFFSET]<<8) | tcp_hdr_arr[TCP_SRC_PORT_OFFSET+1];	//ntoh
	tcp_hdr->th_dport =	(tcp_hdr_arr[TCP_DST_PORT_OFFSET]<<8) | tcp_hdr_arr[TCP_DST_PORT_OFFSET+1];	//ntoh
	tcp_hdr->th_seq = (tcp_hdr_arr[TCP_SEQ_OFFSET]<<24) | (tcp_hdr_arr[TCP_SEQ_OFFSET+1]<<16) | (tcp_hdr_arr[TCP_SEQ_OFFSET+2]<<8) | tcp_hdr_arr[TCP_SEQ_OFFSET+3];	//ntoh
	tcp_hdr->th_ack = (tcp_hdr_arr[TCP_ACK_OFFSET]<<24) | (tcp_hdr_arr[TCP_ACK_OFFSET+1]<<16) | (tcp_hdr_arr[TCP_ACK_OFFSET+2]<<8) | tcp_hdr_arr[TCP_ACK_OFFSET+3];	//ntoh
	tcp_hdr->th_off =	(tcp_hdr_arr[TCP_OFF_OFFSET] & 0xF0)>>4;
	tcp_hdr->th_flags =	tcp_hdr_arr[TCP_FLAGS_OFFSET];
	tcp_hdr->th_win =	(tcp_hdr_arr[TCP_WIN_OFFSET]<<8) | tcp_hdr_arr[TCP_WIN_OFFSET+1];	//ntoh
	tcp_hdr->th_sum =	(tcp_hdr_arr[TCP_SUM_OFFSET]<<8) | tcp_hdr_arr[TCP_SUM_OFFSET+1];	//ntoh
	tcp_hdr->th_urp =	(tcp_hdr_arr[TCP_URP_OFFSET]<<8) | tcp_hdr_arr[TCP_URP_OFFSET+1];	//ntoh	
}

#endif
