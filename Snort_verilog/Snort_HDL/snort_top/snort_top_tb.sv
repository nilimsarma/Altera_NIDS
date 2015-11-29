`ifndef PARSER_SV
`define PARSER_SV

`include "generic/protocols.vh"
`define NULL 0

import TYPEDEFS_P::*;
import TCP_REASSEMBLY_TYPEDEFS_P::*;
import CHANNELS_P::*;

module snort_top_tb;

logic clk;
logic reset;

ch_pkt_stream_struct  ch_pkt_stream_eth;
logic ch_pkt_stream_eth_ready;
	
ch_pkt_stream_struct ch_pkt_stream_tcpseg;
logic ch_pkt_stream_tcpseg_ready;

ch_tcp_inspect_struct ch_tcp_inspect;
logic ch_tcp_inspect_ready;

ch_tcp_segment_struct ch_tcp_segment;
logic ch_tcp_segment_ready;
	
snort_top snort_top_u0
(
.clk,
.reset,

.ch_pkt_stream_eth_in(ch_pkt_stream_eth),
.ch_pkt_stream_eth_in_ready(ch_pkt_stream_eth_ready),
	
.ch_pkt_stream_tcpseg_out(ch_pkt_stream_tcpseg),
.ch_pkt_stream_tcpseg_out_ready(ch_pkt_stream_tcpseg_ready),

.ch_tcp_inspect_out(ch_tcp_inspect),
.ch_tcp_inspect_out_ready(ch_tcp_inspect_ready),

.ch_tcp_segment_out(ch_tcp_segment),
.ch_tcp_segment_out_ready(ch_tcp_segment_ready)

);

typedef enum
{
	s_start,
	s_cont,
	s_end
} state_t;

state_t state_in;

integer		data_file; // file handler
integer		scan_file; // file handler 
uint16_t 	pkt_len;
uint8_t 	data_buf[0:`MAX_ETH_PKT_LEN_BYTES-1];
uint16_t	i;

uint16_t	pkt_offset;
uint16_t	pkt_count;
	
initial begin
	data_file = $fopen("test_data/packet_data.txt", "r");
	if (data_file == `NULL) begin
		$display("tcp_packet handle was NULL");
		$stop;
	end
	
	clk = 0;
	reset = 0;
	#2 reset = 0;
	#4 reset = 1;
end

always begin
	#1 clk = ~clk;
end

//stimulus
always @(posedge clk) begin

	if(~reset) begin
		state_in = s_start;
		pkt_offset = 0;
		
		ch_pkt_stream_eth.valid = 0;
		ch_pkt_stream_eth.sop = 0;
		ch_pkt_stream_eth.eop = 0;
	end
	
	else if(state_in == s_start) begin
		
		if(ch_pkt_stream_eth_ready == 1)	begin
			scan_file = $fscanf(data_file, "%04h", pkt_len);
			for(i=0; i<pkt_len; i++) begin
				scan_file = $fscanf(data_file, "%02h", data_buf[i]);
			end
		
			for(i=0; i<`PARSER_WIN_SIZE_BYTES; i++)	ch_pkt_stream_eth.data[i] = data_buf[i];
			ch_pkt_stream_eth.valid = 1;
			ch_pkt_stream_eth.sop = 1;
			
			pkt_offset = `PARSER_WIN_SIZE_BYTES;
			if(pkt_offset >= pkt_len)	begin
				ch_pkt_stream_eth.eop = 1;
				state_in = s_end;
			end
			else	begin
				ch_pkt_stream_eth.eop = 0;
				state_in = s_cont;
			end
		end		
	end
	
	else if(state_in == s_cont)	begin
		if(ch_pkt_stream_eth_ready == 1)	begin
			for(i=0; i<`PARSER_WIN_SIZE_BYTES; i++)	ch_pkt_stream_eth.data[i] = data_buf[pkt_offset+i];
			ch_pkt_stream_eth.valid = 1;
			ch_pkt_stream_eth.sop = 0;
			
			pkt_offset += `PARSER_WIN_SIZE_BYTES;
			if(pkt_offset >= pkt_len)	begin
				ch_pkt_stream_eth.eop = 1;
				state_in = s_end;
			end
			else	begin
				ch_pkt_stream_eth.eop = 0;
				state_in = s_cont;
			end
		end	
	end
	
	else if(state_in == s_end)	begin
		ch_pkt_stream_eth.valid = 0;
		ch_pkt_stream_eth.sop = 0;
		ch_pkt_stream_eth.eop = 0;
		pkt_offset = 0;
		state_in = s_start;
	end
	
end	//always

integer counter;

tcp_stream_hashkey_t	tcp_stream_hashkey;
uint16_t		tcp_seg_len;

//monitor
always @(posedge clk)	begin
	if(~reset)	begin
		ch_pkt_stream_tcpseg_ready = 0;
		ch_tcp_inspect_ready = 0;
		ch_tcp_segment_ready = 0;
		counter = 0;
	end
	
	else begin
		if(counter == 100) begin
			ch_pkt_stream_tcpseg_ready = 1;
			ch_tcp_inspect_ready = 1;
			ch_tcp_segment_ready = 1;
			counter++;
		end		
		else if(counter > 100)	begin
			if(ch_tcp_segment.valid == 1)	begin
				
				tcp_stream_hashkey = ch_tcp_segment.data.tcp_stream_hashkey;
				tcp_seg_len = ch_tcp_segment.data.tcp_seg_len;

				$display("IPV4 hdr, IP_1 = %d.%d.%d.%d, IP_2 = %d.%d.%d.%d, TCP hdr, PORT_1 = %d, PORT_2 = %d, TCP_SEG_LEN = %d",
					tcp_stream_hashkey.ip_1[31:24],tcp_stream_hashkey.ip_1[23:16],tcp_stream_hashkey.ip_1[15:8],tcp_stream_hashkey.ip_1[7:0],
					tcp_stream_hashkey.ip_2[31:24],tcp_stream_hashkey.ip_2[23:16],tcp_stream_hashkey.ip_2[15:8],tcp_stream_hashkey.ip_2[7:0],
					tcp_stream_hashkey.tcp_port_1, tcp_stream_hashkey.tcp_port_2, tcp_seg_len
				);
			end

			if(ch_tcp_inspect.valid == 1)	begin
				$display("TCP_INSPECT_COMMAND: %s", ch_tcp_inspect.data.tcp_inspect_cmd);
			end
	
		end
		else counter++;
	end
end

endmodule

`endif
