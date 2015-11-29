`ifndef PARSER_SV
`define PARSER_SV

`include "generic/protocols.vh"

import TYPEDEFS_P::*;
import PARSER_TYPEDEFS_P::*;
import PROTOCOLS_TYPEDEFS_P::*;
import CHANNELS_P::*;

module eth_parser
(
	input logic clk,
	input logic reset,
	
	input  ch_pkt_stream_struct  ch_pkt_stream_eth_in,
	output logic ch_pkt_stream_eth_in_ready,
	
	output ch_pkt_stream_struct ch_pkt_stream_ipv4_out,
	input  logic ch_pkt_stream_ipv4_out_ready,
	
	output ch_eth_hdr_struct ch_eth_hdr_out,
	input  logic ch_eth_hdr_out_ready
);

uint8_t eth_hdr_arr[0:`ETH_HDR_LEN-1];
uint8_t eth_hdr_offset;

bool stall_on_ch_pkt_stream_ipv4_out, stall_on_ch_eth_hdr_out;
	
parser_state state;

uint16_t eth_type;

integer i,j,k;

assign ch_pkt_stream_eth_in_ready = ~(stall_on_ch_pkt_stream_ipv4_out | stall_on_ch_eth_hdr_out);

always @(posedge clk) begin
		
	if(~reset) begin
		state = HEADER_INIT;
		stall_on_ch_pkt_stream_ipv4_out = 1;
		stall_on_ch_eth_hdr_out = 1;
		
		eth_hdr_offset = 0;
		
		ch_pkt_stream_ipv4_out.valid = 0;
		ch_pkt_stream_ipv4_out.sop = 0;
		ch_pkt_stream_ipv4_out.eop = 0;
		
		ch_eth_hdr_out.valid = 0;
	end

	else if (state == HEADER_INIT)	begin
		
		stall_on_ch_pkt_stream_ipv4_out = 0;
		stall_on_ch_eth_hdr_out = 0;
		state = HEADER_START;
	end

	else if ( ch_pkt_stream_eth_in_ready == 0 )	begin

		if(stall_on_ch_pkt_stream_ipv4_out == 1)	begin
			if (ch_pkt_stream_ipv4_out_ready == 1)	stall_on_ch_pkt_stream_ipv4_out = 0;
		end
		else begin
			ch_pkt_stream_ipv4_out.valid = 0;
			ch_pkt_stream_ipv4_out.sop   = 0;
			ch_pkt_stream_ipv4_out.eop   = 0;
		end

		if (stall_on_ch_eth_hdr_out == 1) begin
			if (ch_eth_hdr_out_ready == 1)	stall_on_ch_eth_hdr_out = 0;
		end
		else begin
			ch_eth_hdr_out.valid = 0;
		end
	end
	
	else if (ch_pkt_stream_eth_in.valid == 0) begin
		ch_pkt_stream_ipv4_out.valid = 0;
		ch_pkt_stream_ipv4_out.sop   = 0;
		ch_pkt_stream_ipv4_out.eop   = 0;		
		ch_eth_hdr_out.valid = 0;
	end
		
	else if(state == HEADER_START)	begin							
		if(ch_pkt_stream_eth_in.sop == 1)	begin
			eth_hdr_offset = `PARSER_WIN_SIZE_BYTES;
			for(i=0; i<`PARSER_WIN_SIZE_BYTES; i++)	eth_hdr_arr[i] = ch_pkt_stream_eth_in.data[i];
			state = HEADER_CONT;
		end
		ch_eth_hdr_out.valid = 0;
		ch_pkt_stream_ipv4_out.valid = 0;
		ch_pkt_stream_ipv4_out.sop = 0;
		ch_pkt_stream_ipv4_out.eop = 0;
			
	end
	
	else if(state == HEADER_CONT) begin
		for(i=0; i<`PARSER_WIN_SIZE_BYTES; i++)	eth_hdr_arr[eth_hdr_offset+i] = ch_pkt_stream_eth_in.data[i];
		eth_hdr_offset = eth_hdr_offset + `PARSER_WIN_SIZE_BYTES;
		if(eth_hdr_offset > (`ETH_HDR_LEN -`PARSER_WIN_SIZE_BYTES))	state = HEADER_END_PAYLOAD;
	end
	
	else if(state == HEADER_END_PAYLOAD) begin
	
		for(i=0; i<`ETH_HDR_LEN_OFFSET_WIN; i++)	eth_hdr_arr[eth_hdr_offset+i] = ch_pkt_stream_eth_in.data[i];
		ch_eth_hdr_out.valid = 1;
		
		//check for stall
		if(ch_eth_hdr_out_ready == 0)	stall_on_ch_eth_hdr_out = 1;
		
		eth_type = {ch_pkt_stream_eth_in.data[0],ch_pkt_stream_eth_in.data[1]};		
		if(eth_type == `ETH_TYPE_IPV4)	begin
		
			for(i=0; i<`PARSER_WIN_SIZE_BYTES; i++)	ch_pkt_stream_ipv4_out.data[i] = ch_pkt_stream_eth_in.data[i];
			ch_pkt_stream_ipv4_out.valid = 1;
			ch_pkt_stream_ipv4_out.sop = 1;
			ch_pkt_stream_ipv4_out.eop = 0;
			
			//check for stall
			if (ch_pkt_stream_ipv4_out_ready == 0)	stall_on_ch_pkt_stream_ipv4_out = 1;
			
			state = PAYLOAD;
		end	
		else	state = UNKNOWN;
	end
	
	else if (state == PAYLOAD) begin
		ch_eth_hdr_out.valid = 0;
		
		for(i=0; i<`PARSER_WIN_SIZE_BYTES; i++)	ch_pkt_stream_ipv4_out.data[i] = ch_pkt_stream_eth_in.data[i];
		ch_pkt_stream_ipv4_out.valid = 1;
		ch_pkt_stream_ipv4_out.sop = 0;
		ch_pkt_stream_ipv4_out.eop = ch_pkt_stream_eth_in.eop;
		
		//check for stall
		if (ch_pkt_stream_ipv4_out_ready == 0)	stall_on_ch_pkt_stream_ipv4_out = 1;
		
		if (ch_pkt_stream_eth_in.eop == 1)	state = HEADER_START;
	end

	else if (state == UNKNOWN)	begin
		ch_eth_hdr_out.valid = 0;
		
		ch_pkt_stream_ipv4_out.valid = 1;
		ch_pkt_stream_ipv4_out.sop = 0;
		ch_pkt_stream_ipv4_out.eop = ch_pkt_stream_eth_in.eop;
		
		if (ch_pkt_stream_eth_in.eop == 1)	state = HEADER_START;
	end
end	//always

always_comb begin
	//fill struct
	for(j=0; j<`ETH_DST_SIZE; j++)	begin
		ch_eth_hdr_out.data.eth_dst[j] = eth_hdr_arr[`ETH_DST_OFFSET+j];
	end
	for(j=0; j<`ETH_SRC_SIZE; j++)	begin
		ch_eth_hdr_out.data.eth_src[j] = eth_hdr_arr[`ETH_SRC_OFFSET+j];
	end

	ch_eth_hdr_out.data.eth_type = {eth_hdr_arr[`ETH_TYPE_OFFSET],eth_hdr_arr[`ETH_TYPE_OFFSET+1]};
end

endmodule


module ipv4_parser(

	input clk, 
	input reset,

	input ch_pkt_stream_struct ch_pkt_stream_ipv4_in,
	output logic ch_pkt_stream_ipv4_in_ready,
	
	output ch_pkt_stream_struct ch_pkt_stream_tcp_out,
	input	logic ch_pkt_stream_tcp_out_ready,
	
	output ch_ipv4_hdr_struct ch_ipv4_hdr_out,
	input logic ch_ipv4_hdr_out_ready
);

uint8_t ipv4_hdr_arr[0:`IPV4_HDR_LEN-1];
uint8_t ipv4_hdr_offset;
parser_state state;

bool stall_on_ch_pkt_stream_tcp_out, stall_on_ch_ipv4_hdr_out;

uint8_t ipv4_hdr_with_opt_len;
integer i;

assign ch_pkt_stream_ipv4_in_ready = ~(stall_on_ch_pkt_stream_tcp_out | stall_on_ch_ipv4_hdr_out);
always @(posedge clk)	begin

	if(~reset)	begin
		
		state = HEADER_INIT;
		stall_on_ch_pkt_stream_tcp_out = 1;
		stall_on_ch_ipv4_hdr_out = 1;
		
		ipv4_hdr_offset = 0;
		
		ch_pkt_stream_tcp_out.valid = 0;
		ch_pkt_stream_tcp_out.sop = 0;
		ch_pkt_stream_tcp_out.eop = 0;
		
		ch_ipv4_hdr_out.valid = 0;
	end
	
	else if ( state == HEADER_INIT ) begin

		stall_on_ch_pkt_stream_tcp_out = 0;
		stall_on_ch_ipv4_hdr_out = 0;
		state = HEADER_START;
	end
 
	else if ( ch_pkt_stream_ipv4_in_ready == 0 )	begin
	
		if (stall_on_ch_pkt_stream_tcp_out == 1)	begin
			if (ch_pkt_stream_tcp_out_ready == 1)	stall_on_ch_pkt_stream_tcp_out = 0;
		end
		else begin
			ch_pkt_stream_tcp_out.valid = 0;
			ch_pkt_stream_tcp_out.sop = 0;
			ch_pkt_stream_tcp_out.eop = 0;
		end
		
		if(stall_on_ch_ipv4_hdr_out == 1)	begin
			if (ch_ipv4_hdr_out_ready == 1)			stall_on_ch_ipv4_hdr_out = 0;
		end
		else begin
			ch_ipv4_hdr_out.valid = 0;
		end
	end
	
	else if (ch_pkt_stream_ipv4_in.valid == 0)	begin
		ch_ipv4_hdr_out.valid = 0;
		ch_pkt_stream_tcp_out.valid = 0;
		ch_pkt_stream_tcp_out.sop = 0;
		ch_pkt_stream_tcp_out.eop = 0;
	end
	
	else if (state == HEADER_START)	begin

		if (ch_pkt_stream_ipv4_in.sop == 1)	begin
			for (i=`ETH_HDR_LEN_OFFSET_WIN; i<`PARSER_WIN_SIZE_BYTES; i++)	ipv4_hdr_arr[i-`ETH_HDR_LEN_OFFSET_WIN] = ch_pkt_stream_ipv4_in.data[i];
			state = HEADER_CONT;
			ipv4_hdr_offset = `PARSER_WIN_SIZE_BYTES - `ETH_HDR_LEN_OFFSET_WIN;
		end
		
		ch_ipv4_hdr_out.valid = 0;
		ch_pkt_stream_tcp_out.valid = 0;
		ch_pkt_stream_tcp_out.sop = 0;
		ch_pkt_stream_tcp_out.eop = 0;
	end
	
	else if (state == HEADER_CONT)	begin
		for (i=0; i<`PARSER_WIN_SIZE_BYTES; i++)	ipv4_hdr_arr[ipv4_hdr_offset+i] = ch_pkt_stream_ipv4_in.data[i];			
		ipv4_hdr_offset = ipv4_hdr_offset + `PARSER_WIN_SIZE_BYTES;
		
		if (ipv4_hdr_offset > (`IPV4_HDR_LEN - `PARSER_WIN_SIZE_BYTES))	begin
			if (ipv4_hdr_with_opt_len == `IPV4_HDR_LEN)	state = HEADER_END_PAYLOAD;
			else	state = HEADER_END_OPTIONS;
		end
	end
	
	else if (state == HEADER_END_PAYLOAD)	begin
		for(i=0; i<`IPV4_HDR_LEN_OFFSET_WIN; i++)	ipv4_hdr_arr[ipv4_hdr_offset+i] = ch_pkt_stream_ipv4_in.data[i];
		ch_ipv4_hdr_out.valid = 1;
		//check for stall
		if(ch_ipv4_hdr_out_ready == 0)	stall_on_ch_ipv4_hdr_out = 1;
		
		//tcp parser
		if (ipv4_hdr_arr[`IPV4_PROTO_OFFSET] == `IPV4_PROTO_TCP)	begin
			for (i=0 ; i<`PARSER_WIN_SIZE_BYTES; i++)	ch_pkt_stream_tcp_out.data[i] = ch_pkt_stream_ipv4_in.data[i];			
			ch_pkt_stream_tcp_out.valid = 1;
			ch_pkt_stream_tcp_out.sop = 1;
			ch_pkt_stream_tcp_out.eop = ch_pkt_stream_ipv4_in.eop;

			//check for stall
			if (ch_pkt_stream_tcp_out_ready == 0)	stall_on_ch_pkt_stream_tcp_out = 1;
		
			state = PAYLOAD;
		end	
		else state = UNKNOWN;
		
		if(ch_pkt_stream_ipv4_in.eop == 1)	state = HEADER_START;
	end
	
	else if (state == HEADER_END_OPTIONS)	begin

		//pragma unroll
		for (i=0; i<`IPV4_HDR_LEN_OFFSET_WIN; i++) ipv4_hdr_arr[ipv4_hdr_offset+i] = ch_pkt_stream_ipv4_in.data[i];
		ch_ipv4_hdr_out.valid = 1;
		//check for stall
		if(ch_ipv4_hdr_out_ready == 0)	stall_on_ch_ipv4_hdr_out = 1;
		
		ipv4_hdr_offset = ipv4_hdr_offset + `PARSER_WIN_SIZE_BYTES;
		
		if (ipv4_hdr_offset > (ipv4_hdr_with_opt_len - `PARSER_WIN_SIZE_BYTES) )	state = HEADER_OPTIONS_END_PAYLOAD;
		else	state = HEADER_OPTIONS_CONT;
	end
	
	else if (state == HEADER_OPTIONS_CONT)	begin
		ch_ipv4_hdr_out.valid = 0;
		
		ipv4_hdr_offset = ipv4_hdr_offset + `PARSER_WIN_SIZE_BYTES;			
		if (ipv4_hdr_offset > (ipv4_hdr_with_opt_len - `PARSER_WIN_SIZE_BYTES) )
			state = HEADER_OPTIONS_END_PAYLOAD;
	end
	
	else if (state == HEADER_OPTIONS_END_PAYLOAD)	begin
		ch_ipv4_hdr_out.valid = 0;

		//tcp parser
		if (ipv4_hdr_arr[`IPV4_PROTO_OFFSET] == `IPV4_PROTO_TCP)	begin
			for (i=0; i<`PARSER_WIN_SIZE_BYTES; i++)	ch_pkt_stream_tcp_out.data[i] = ch_pkt_stream_ipv4_in.data[i];
			ch_pkt_stream_tcp_out.valid = 1;
			ch_pkt_stream_tcp_out.sop = 1;
			ch_pkt_stream_tcp_out.eop = ch_pkt_stream_ipv4_in.eop;

			//check for stall
			if (ch_pkt_stream_tcp_out_ready == 0)	stall_on_ch_pkt_stream_tcp_out = 1;
		
			state = PAYLOAD;
		end	
		else	state = UNKNOWN;
		
		if(ch_pkt_stream_ipv4_in.eop == 1)	state = HEADER_START;		
	end	
	
	else if (state == PAYLOAD) begin
		ch_ipv4_hdr_out.valid = 0;
		
		for (i=0; i<`PARSER_WIN_SIZE_BYTES; i++)	ch_pkt_stream_tcp_out.data[i] = ch_pkt_stream_ipv4_in.data[i];
		ch_pkt_stream_tcp_out.valid = 1;
		ch_pkt_stream_tcp_out.sop = 0;
		ch_pkt_stream_tcp_out.eop = ch_pkt_stream_ipv4_in.eop;
		
		//check for stall
		if (ch_pkt_stream_tcp_out_ready == 0)	stall_on_ch_pkt_stream_tcp_out = 1;
		
		if(ch_pkt_stream_ipv4_in.eop == 1)	state = HEADER_START;
	end	

	else if (state == UNKNOWN) begin
		ch_ipv4_hdr_out.valid = 0;
		
		ch_pkt_stream_tcp_out.valid = 0;
		ch_pkt_stream_tcp_out.sop = 0;
		ch_pkt_stream_tcp_out.eop = ch_pkt_stream_ipv4_in.eop;
		
		//check for stall
		if (ch_pkt_stream_tcp_out_ready == 0)	stall_on_ch_pkt_stream_tcp_out = 1;
		
		if(ch_pkt_stream_ipv4_in.eop == 1)	state = HEADER_START;
	end	
end	//endalways


always_comb	begin
	ipv4_hdr_with_opt_len = (ipv4_hdr_arr[`IPV4_V_HL_OFFSET] & 8'h0F)<<2;		//bits 3-0
	
	ch_ipv4_hdr_out.data.ip_v   = (ipv4_hdr_arr[`IPV4_V_HL_OFFSET] & 8'hF0)>>4;	//bits 7-4
	ch_ipv4_hdr_out.data.ip_hl  = (ipv4_hdr_arr[`IPV4_V_HL_OFFSET] & 8'h0F);	//bits 3-0
	ch_ipv4_hdr_out.data.ip_tos = ipv4_hdr_arr[`IPV4_TOS_OFFSET];
	ch_ipv4_hdr_out.data.ip_len = {ipv4_hdr_arr[`IPV4_LEN_OFFSET], ipv4_hdr_arr[`IPV4_LEN_OFFSET+1]}; //ntoh
	ch_ipv4_hdr_out.data.ip_id  = {ipv4_hdr_arr[`IPV4_ID_OFFSET], ipv4_hdr_arr[`IPV4_ID_OFFSET+1]};	  //ntoh
	ch_ipv4_hdr_out.data.ip_off = {ipv4_hdr_arr[`IPV4_OFF_OFFSET], ipv4_hdr_arr[`IPV4_OFF_OFFSET+1]}; //ntoh
	ch_ipv4_hdr_out.data.ip_ttl = ipv4_hdr_arr[`IPV4_TTL_OFFSET];
	ch_ipv4_hdr_out.data.ip_p   = ipv4_hdr_arr[`IPV4_PROTO_OFFSET];
	ch_ipv4_hdr_out.data.ip_sum = {ipv4_hdr_arr[`IPV4_SUM_OFFSET], ipv4_hdr_arr[`IPV4_SUM_OFFSET+1]}; //ntoh		
	ch_ipv4_hdr_out.data.ip_src = {ipv4_hdr_arr[`IPV4_SRC_OFFSET], ipv4_hdr_arr[`IPV4_SRC_OFFSET+1], ipv4_hdr_arr[`IPV4_SRC_OFFSET+2], ipv4_hdr_arr[`IPV4_SRC_OFFSET+3]};
	ch_ipv4_hdr_out.data.ip_dst = {ipv4_hdr_arr[`IPV4_DST_OFFSET], ipv4_hdr_arr[`IPV4_DST_OFFSET+1], ipv4_hdr_arr[`IPV4_DST_OFFSET+2], ipv4_hdr_arr[`IPV4_DST_OFFSET+3]};
end
		
endmodule 

module tcp_parser(
	input clk, 
	input reset,

	input ch_pkt_stream_struct ch_pkt_stream_tcp_in,
	output logic ch_pkt_stream_tcp_in_ready,
	
	output ch_pkt_stream_struct ch_pkt_stream_tcpseg_out,
	input	logic ch_pkt_stream_tcpseg_out_ready,
	
	output ch_tcp_hdr_struct ch_tcp_hdr_out,
	input logic ch_tcp_hdr_out_ready
);

uint8_t tcp_hdr_arr[`TCP_HDR_LEN];
uint8_t tcp_hdr_offset;
parser_state state;

bool stall_on_ch_pkt_stream_tcpseg_out, stall_on_ch_tcp_hdr_out;

uint8_t tcp_hdr_with_opt_len;
integer i;

assign ch_pkt_stream_tcp_in_ready = ~(stall_on_ch_pkt_stream_tcpseg_out | stall_on_ch_tcp_hdr_out);
always @(posedge clk)	begin

	if(~reset)	begin
		
		state = HEADER_INIT;
		stall_on_ch_pkt_stream_tcpseg_out = 1;
		stall_on_ch_tcp_hdr_out = 1;
		
		tcp_hdr_offset = 0;
		
		ch_pkt_stream_tcpseg_out.valid = 0;
		ch_pkt_stream_tcpseg_out.sop = 0;
		ch_pkt_stream_tcpseg_out.eop = 0;
		
		ch_tcp_hdr_out.valid = 0;
	end

	else if ( state == HEADER_INIT ) begin

		stall_on_ch_pkt_stream_tcpseg_out = 0;
		stall_on_ch_tcp_hdr_out = 0;
		state = HEADER_START;
	end

	else if ( ch_pkt_stream_tcp_in_ready == 0 ) begin

		if(stall_on_ch_pkt_stream_tcpseg_out == 1)	begin
			if (ch_pkt_stream_tcpseg_out_ready == 1)  stall_on_ch_pkt_stream_tcpseg_out = 0;
		end
		else begin
			ch_pkt_stream_tcpseg_out.valid = 0;
			ch_pkt_stream_tcpseg_out.sop = 0;
			ch_pkt_stream_tcpseg_out.eop = 0;	
		end
		
		if (stall_on_ch_tcp_hdr_out == 1)	begin
			if (ch_tcp_hdr_out_ready == 1)	stall_on_ch_tcp_hdr_out = 0;
		end
		else begin
			ch_tcp_hdr_out.valid = 0;
		end
	end
	
	else if (ch_pkt_stream_tcp_in.valid == 0)  begin
		ch_tcp_hdr_out.valid = 0;
		ch_pkt_stream_tcpseg_out.valid = 0;
		ch_pkt_stream_tcpseg_out.sop = 0;
		ch_pkt_stream_tcpseg_out.eop = 0;		
	end
	
	else if (state == HEADER_START)  begin
		if (ch_pkt_stream_tcp_in.sop == 1)  begin
			for (i=`IPV4_HDR_LEN_OFFSET_WIN; i<`PARSER_WIN_SIZE_BYTES; i++)  tcp_hdr_arr[i-`IPV4_HDR_LEN_OFFSET_WIN] = ch_pkt_stream_tcp_in.data[i];
			state = HEADER_CONT;
			tcp_hdr_offset = `PARSER_WIN_SIZE_BYTES - `IPV4_HDR_LEN_OFFSET_WIN;
		end
		
		ch_tcp_hdr_out.valid = 0;
		ch_pkt_stream_tcpseg_out.valid = 0;
		ch_pkt_stream_tcpseg_out.sop = 0;
		ch_pkt_stream_tcpseg_out.eop = 0;
	end
	
	else if (state == HEADER_CONT)  begin
		for (i=0; i<`PARSER_WIN_SIZE_BYTES; i++)		tcp_hdr_arr[tcp_hdr_offset+i] = ch_pkt_stream_tcp_in.data[i];
		tcp_hdr_offset = tcp_hdr_offset + `PARSER_WIN_SIZE_BYTES;
		
		if (tcp_hdr_offset > (`IPV4_HDR_LEN - `PARSER_WIN_SIZE_BYTES))  begin				
			if (tcp_hdr_with_opt_len == `TCP_HDR_LEN)  state = HEADER_END_PAYLOAD;
			else	state = HEADER_END_OPTIONS;
		end
	end
	
	else if (state == HEADER_END_PAYLOAD)  begin
		for (i=0; i<`TCP_HDR_LEN_OFFSET_WIN; i++)	tcp_hdr_arr[tcp_hdr_offset+i] = ch_pkt_stream_tcp_in.data[i];
		
		ch_tcp_hdr_out.valid = 1;	
		//check for stall
		if(ch_tcp_hdr_out_ready == 0)	stall_on_ch_tcp_hdr_out = 1;
		
		//tcp parser
		if ((ch_tcp_hdr_out.data.th_sport == `TCP_PORT_HTTP) || (ch_tcp_hdr_out.data.th_dport == `TCP_PORT_HTTP))  begin
			for (i=0; i<`PARSER_WIN_SIZE_BYTES; i++)  ch_pkt_stream_tcpseg_out.data[i] = ch_pkt_stream_tcp_in.data[i];
			ch_pkt_stream_tcpseg_out.valid = 1;
			ch_pkt_stream_tcpseg_out.sop = 1;
			ch_pkt_stream_tcpseg_out.eop = ch_pkt_stream_tcp_in.eop;

			if (ch_pkt_stream_tcpseg_out_ready == 0)  stall_on_ch_pkt_stream_tcpseg_out = 1;
			state = PAYLOAD;
		end
		else state = UNKNOWN;
		
		if(ch_pkt_stream_tcp_in.eop == 1)	state = HEADER_START;
	end
	
	else if (state == HEADER_END_OPTIONS)  begin

		//pragma unroll
		for (i=0; i<`TCP_HDR_LEN_OFFSET_WIN; i++) tcp_hdr_arr[tcp_hdr_offset+i] = ch_pkt_stream_tcp_in.data[i];
		
		ch_tcp_hdr_out.valid = 1;	
		//check for stall
		if(ch_tcp_hdr_out_ready == 0)	stall_on_ch_tcp_hdr_out = 1;
		
		tcp_hdr_offset = tcp_hdr_offset + `PARSER_WIN_SIZE_BYTES;
		
		if (tcp_hdr_offset > (tcp_hdr_with_opt_len - `PARSER_WIN_SIZE_BYTES))  state = HEADER_OPTIONS_END_PAYLOAD;
		else 	state = HEADER_OPTIONS_CONT;
	end
	
	else if (state == HEADER_OPTIONS_CONT)  begin
		ch_tcp_hdr_out.valid = 0;
		tcp_hdr_offset = tcp_hdr_offset + `PARSER_WIN_SIZE_BYTES;			
		if (tcp_hdr_offset > (tcp_hdr_with_opt_len - `PARSER_WIN_SIZE_BYTES)) 	state = HEADER_OPTIONS_END_PAYLOAD;
	end
	
	else if (state == HEADER_OPTIONS_END_PAYLOAD)  begin
		ch_tcp_hdr_out.valid = 0;
		
		//tcp parser
		if ((ch_tcp_hdr_out.data.th_sport == `TCP_PORT_HTTP) || (ch_tcp_hdr_out.data.th_dport == `TCP_PORT_HTTP))  begin
			for (i=0; i<`PARSER_WIN_SIZE_BYTES; i++) 	ch_pkt_stream_tcpseg_out.data[i] = ch_pkt_stream_tcp_in.data[i];
			ch_pkt_stream_tcpseg_out.valid = 1;
			ch_pkt_stream_tcpseg_out.sop = 1;
			ch_pkt_stream_tcpseg_out.eop = ch_pkt_stream_tcp_in.eop;

			if (ch_pkt_stream_tcpseg_out_ready == 0)  stall_on_ch_pkt_stream_tcpseg_out = 1;
			state = PAYLOAD;
		end	
		else	state = UNKNOWN;
		
		if(ch_pkt_stream_tcp_in.eop == 1)	state = HEADER_START;
	end
	
	else if (state == PAYLOAD)  begin
		ch_tcp_hdr_out.valid = 0;
		
		for (i=0; i<`PARSER_WIN_SIZE_BYTES; i++)  ch_pkt_stream_tcpseg_out.data[i] = ch_pkt_stream_tcp_in.data[i];
		ch_pkt_stream_tcpseg_out.valid = 1;
		ch_pkt_stream_tcpseg_out.sop = 0;
		ch_pkt_stream_tcpseg_out.eop = ch_pkt_stream_tcp_in.eop;
		
		if (ch_pkt_stream_tcpseg_out_ready == 0)  stall_on_ch_pkt_stream_tcpseg_out = 1;
		
		if(ch_pkt_stream_tcp_in.eop == 1)	state = HEADER_START;
	end

	else if (state == UNKNOWN)  begin
		ch_tcp_hdr_out.valid = 0;
		
		ch_pkt_stream_tcpseg_out.valid = 1;
		ch_pkt_stream_tcpseg_out.sop = 0;
		ch_pkt_stream_tcpseg_out.eop = ch_pkt_stream_tcp_in.eop;
		
		if(ch_pkt_stream_tcp_in.eop == 1)	state = HEADER_START;
	end	
end //always

always_comb	begin

	tcp_hdr_with_opt_len = (tcp_hdr_arr[`TCP_OFF_OFFSET] & 8'hF0)>>2;
	
	ch_tcp_hdr_out.data.th_sport =	{tcp_hdr_arr[`TCP_SRC_PORT_OFFSET], tcp_hdr_arr[`TCP_SRC_PORT_OFFSET+1]};	//ntoh
	ch_tcp_hdr_out.data.th_dport =	{tcp_hdr_arr[`TCP_DST_PORT_OFFSET], tcp_hdr_arr[`TCP_DST_PORT_OFFSET+1]};	//ntoh
	ch_tcp_hdr_out.data.th_seq = 	{tcp_hdr_arr[`TCP_SEQ_OFFSET], tcp_hdr_arr[`TCP_SEQ_OFFSET+1], tcp_hdr_arr[`TCP_SEQ_OFFSET+2], tcp_hdr_arr[`TCP_SEQ_OFFSET+3]};	//ntoh
	ch_tcp_hdr_out.data.th_ack = 	{tcp_hdr_arr[`TCP_ACK_OFFSET], tcp_hdr_arr[`TCP_ACK_OFFSET+1], tcp_hdr_arr[`TCP_ACK_OFFSET+2], tcp_hdr_arr[`TCP_ACK_OFFSET+3]}; //ntoh
	ch_tcp_hdr_out.data.th_off =	(tcp_hdr_arr[`TCP_OFF_OFFSET] & 8'hF0)>>4;
	ch_tcp_hdr_out.data.th_flags =	tcp_hdr_arr[`TCP_FLAGS_OFFSET];
	ch_tcp_hdr_out.data.th_win =	{tcp_hdr_arr[`TCP_WIN_OFFSET], tcp_hdr_arr[`TCP_WIN_OFFSET+1]};	//ntoh
	ch_tcp_hdr_out.data.th_sum =	{tcp_hdr_arr[`TCP_SUM_OFFSET], tcp_hdr_arr[`TCP_SUM_OFFSET+1]};	//ntoh
	ch_tcp_hdr_out.data.th_urp =	{tcp_hdr_arr[`TCP_URP_OFFSET], tcp_hdr_arr[`TCP_URP_OFFSET+1]};	//ntoh		
	
end

endmodule


module parser
(
	input logic clk,
	input logic reset,
	
	input  ch_pkt_stream_struct  ch_pkt_stream_eth_in,
	output logic ch_pkt_stream_eth_in_ready,
	
	output ch_pkt_stream_struct ch_pkt_stream_tcpseg_out,
	input  logic ch_pkt_stream_tcpseg_out_ready,
	
	output ch_eth_hdr_struct ch_eth_hdr_out,
	input  logic ch_eth_hdr_out_ready,

	output ch_ipv4_hdr_struct ch_ipv4_hdr_out,
	input  logic ch_ipv4_hdr_out_ready,

	output ch_tcp_hdr_struct ch_tcp_hdr_out,
	input  logic ch_tcp_hdr_out_ready

);

ch_pkt_stream_struct ch_pkt_stream_ipv4;
logic ch_pkt_stream_ipv4_ready;
ch_pkt_stream_struct ch_pkt_stream_tcp;
logic ch_pkt_stream_tcp_ready;

eth_parser		eth_parser_u0(
.clk,
.reset,

.ch_pkt_stream_eth_in,
.ch_pkt_stream_eth_in_ready,
	
.ch_pkt_stream_ipv4_out(ch_pkt_stream_ipv4),
.ch_pkt_stream_ipv4_out_ready(ch_pkt_stream_ipv4_ready),
	
.ch_eth_hdr_out,
.ch_eth_hdr_out_ready
);

ipv4_parser		ipv4_parser_u0(
.clk, 
.reset,

.ch_pkt_stream_ipv4_in(ch_pkt_stream_ipv4),
.ch_pkt_stream_ipv4_in_ready(ch_pkt_stream_ipv4_ready),

.ch_pkt_stream_tcp_out(ch_pkt_stream_tcp),
.ch_pkt_stream_tcp_out_ready(ch_pkt_stream_tcp_ready),

.ch_ipv4_hdr_out,
.ch_ipv4_hdr_out_ready
);

tcp_parser		tcp_parser_u0(
.clk, 
.reset,

.ch_pkt_stream_tcp_in(ch_pkt_stream_tcp),
.ch_pkt_stream_tcp_in_ready(ch_pkt_stream_tcp_ready),

.ch_pkt_stream_tcpseg_out,
.ch_pkt_stream_tcpseg_out_ready,

.ch_tcp_hdr_out,
.ch_tcp_hdr_out_ready
);
endmodule

`endif
