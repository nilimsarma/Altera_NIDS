#ifndef HASH_UTILS
#define HASH_UTILS

#include "typedefs.h"
#include "protocols.h"
//#include "read_eth_mac.h"
//#include "parser.h"
#include "tcp_reassembly.h"
//#include "hash.h"

uint32_t hash_func (tcp_stream_hashkey_t tcp_stream_hashkey)
{
	return (tcp_stream_hashkey.ip_1 ^ tcp_stream_hashkey.ip_2 ^	tcp_stream_hashkey.tcp_port_1 ^ tcp_stream_hashkey.tcp_port_2);
}

bool hashkey_comp_func (tcp_stream_hashkey_t tcp_stream_hashkey1, tcp_stream_hashkey_t tcp_stream_hashkey2)
{
	return ((tcp_stream_hashkey1.ip_1 == tcp_stream_hashkey2.ip_1) & 
			(tcp_stream_hashkey1.ip_2 == tcp_stream_hashkey2.ip_2) & 
			(tcp_stream_hashkey1.tcp_port_1 == tcp_stream_hashkey2.tcp_port_1) & 
			(tcp_stream_hashkey1.tcp_port_2 == tcp_stream_hashkey2.tcp_port_2));
}	

#endif