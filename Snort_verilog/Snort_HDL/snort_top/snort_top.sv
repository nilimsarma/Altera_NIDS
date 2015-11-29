`ifndef SNORT_TOP_SV
`define SNORT_TOP_SV

import CHANNELS_P::*;

module snort_top (

input logic clk,
input logic reset,

input  ch_pkt_stream_struct  ch_pkt_stream_eth_in,
output logic ch_pkt_stream_eth_in_ready,
	
output ch_pkt_stream_struct ch_pkt_stream_tcpseg_out,
input  logic ch_pkt_stream_tcpseg_out_ready,

output ch_tcp_inspect_struct ch_tcp_inspect_out,
input logic ch_tcp_inspect_out_ready,

output ch_tcp_segment_struct ch_tcp_segment_out,
input logic ch_tcp_segment_out_ready

);

ch_eth_hdr_struct ch_eth_hdr;
logic ch_eth_hdr_ready;

ch_ipv4_hdr_struct ch_ipv4_hdr;
logic ch_ipv4_hdr_ready;

ch_tcp_hdr_struct ch_tcp_hdr;
logic ch_tcp_hdr_ready;

ch_hash_cmd_intf_struct  ch_hash_cmd_intf;
logic ch_hash_cmd_intf_ready;
	
ch_hash_ret_intf_struct  ch_hash_ret_intf;
logic	ch_hash_ret_intf_ready;


parser	parser_u0
(
.clk,
.reset,
	
.ch_pkt_stream_eth_in,
.ch_pkt_stream_eth_in_ready,
	
.ch_pkt_stream_tcpseg_out,
.ch_pkt_stream_tcpseg_out_ready,
	
.ch_eth_hdr_out(ch_eth_hdr),
.ch_eth_hdr_out_ready(ch_eth_hdr_ready),

.ch_ipv4_hdr_out(ch_ipv4_hdr),
.ch_ipv4_hdr_out_ready(ch_ipv4_hdr_ready),

.ch_tcp_hdr_out(ch_tcp_hdr),
.ch_tcp_hdr_out_ready(ch_tcp_hdr_ready)

);

tcp_reassembly	tcp_reassembly_u0
(
.clk,
.reset,
	

.ch_eth_hdr_in(ch_eth_hdr),
.ch_eth_hdr_in_ready(ch_eth_hdr_ready),

.ch_ipv4_hdr_in(ch_ipv4_hdr),
.ch_ipv4_hdr_in_ready(ch_ipv4_hdr_ready),

.ch_tcp_hdr_in(ch_tcp_hdr),
.ch_tcp_hdr_in_ready(ch_tcp_hdr_ready),

.ch_hash_ret_intf_in(ch_hash_ret_intf),
.ch_hash_ret_intf_in_ready(ch_hash_ret_intf_ready),
	
.ch_hash_cmd_intf_out(ch_hash_cmd_intf),
.ch_hash_cmd_intf_out_ready(ch_hash_cmd_intf_ready),
	
.ch_tcp_inspect_out,
.ch_tcp_inspect_out_ready,
	
.ch_tcp_segment_out,
.ch_tcp_segment_out_ready
);

hash hash_u0
(
.clk,
.reset,
	
.ch_hash_cmd_intf_in(ch_hash_cmd_intf),
.ch_hash_cmd_intf_in_ready(ch_hash_cmd_intf_ready),
	
.ch_hash_ret_intf_out(ch_hash_ret_intf),
.ch_hash_ret_intf_out_ready(ch_hash_ret_intf_ready)
);

endmodule

`endif

