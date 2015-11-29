`ifndef CHANNELS_SV
`define CHANNELS_SV

`include "generic/protocols.vh"
package CHANNELS_P;

import TYPEDEFS_P::*;
import PROTOCOLS_TYPEDEFS_P::*;
import TCP_REASSEMBLY_TYPEDEFS_P::*;
import HASH_TYPEDEFS_P::*;

typedef struct {
	uint8_t data[0:`PARSER_WIN_SIZE_BYTES-1];
	logic valid;
	logic sop;
	logic eop;
} ch_pkt_stream_struct;

typedef struct {
	eth_hdr_struct data;
	logic valid;
} ch_eth_hdr_struct;

typedef struct {
	ipv4_hdr_struct data;
	logic valid;
} ch_ipv4_hdr_struct;

typedef struct {
	tcp_hdr_struct data;
	logic valid;
} ch_tcp_hdr_struct;

typedef struct	{
	hash_cmd_intf_t data;
	logic valid;
} ch_hash_cmd_intf_struct;

typedef struct	{
	hash_ret_intf_t data;
	logic valid;
} ch_hash_ret_intf_struct;

typedef struct
{
	tcp_inspect_data_flow_t data;
	logic valid;
} ch_tcp_inspect_struct;

typedef struct
{
	tcp_segment_struct_t data;
	logic valid;
} ch_tcp_segment_struct;

endpackage

`endif
