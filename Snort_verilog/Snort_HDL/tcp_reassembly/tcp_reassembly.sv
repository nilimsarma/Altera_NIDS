`ifndef TCP_REASSEMBLY_SV
`define TCP_REASSEMBLY_SV

`include "tcp_reassembly/tcp_reassembly.vh"
`include "generic/protocols.vh"

import TYPEDEFS_P::*;
import PROTOCOLS_TYPEDEFS_P::*;
import TCP_REASSEMBLY_TYPEDEFS_P::*;
import HASH_TYPEDEFS_P::*;
import CHANNELS_P::*;


module tcp_reassembly
(
	input logic clk,
	input logic reset,
	
	//read channel
	input ch_eth_hdr_struct ch_eth_hdr_in,
	output logic ch_eth_hdr_in_ready,

	input ch_ipv4_hdr_struct ch_ipv4_hdr_in,
	output logic ch_ipv4_hdr_in_ready,

	input ch_tcp_hdr_struct ch_tcp_hdr_in,
	output logic ch_tcp_hdr_in_ready,

	input ch_hash_ret_intf_struct ch_hash_ret_intf_in,
	output logic ch_hash_ret_intf_in_ready,
	
	//write channel
	output ch_hash_cmd_intf_struct ch_hash_cmd_intf_out,
	input logic ch_hash_cmd_intf_out_ready,
	
	output ch_tcp_inspect_struct ch_tcp_inspect_out,
	input logic ch_tcp_inspect_out_ready,
	
	output ch_tcp_segment_struct ch_tcp_segment_out,
	input logic ch_tcp_segment_out_ready
);

	tcp_stream_hashkey_t	tcp_stream_hashkey;
	tcp_stream_hash_data_t	tcp_stream_hash_data;
	hash_node_addr_t 	hash_node_addr;
	hash_cmd_t 		hash_cmd;
	hash_ret_t 		hash_ret;
	
	bool 			dir; 
	uint8_t 		tcp_flags;
	stream_state_t  	stream_state, stream_state_prev;
	tcp_inspect_cmd_t 	tcp_inspect_cmd;
	tcp_reassembly_state_t 	tcp_reassembly_state, tcp_reassembly_state_return;

	bool 			wr_ch_hash_module, wr_ch_tcp_inspect_data_flow;
	bool 			rd_ch_hash_module;
	logic [2:0]		wr_channel;	//{wr_ch_hash_module, wr_ch_tcp_inspect_data_flow, wr_ch_tcp_inspect}

	eth_hdr_struct		eth_hdr;
	ipv4_hdr_struct		ipv4_hdr;
	tcp_hdr_struct		tcp_hdr;

	uint8_t 		slot;			
	uint16_t 		tcp_seg_len;

	bool err;

	uint16_t stream_state_update_mem_addr;
	uint8_t  stream_state_update_mem_data;
	
	tcp_inspect_data_flow_t tcp_inspect_data_flow;
	tcp_segment_struct_t tcp_segment_struct;

	bool ack_flag, rst_flag, syn_flag, fin_flag;

	//generated
	uint8_t stream_state_update_mem[512] = '{8'h01, 8'h01, 8'h10, 8'h01, 8'h01, 8'h01, 8'h01, 8'h01, 8'h01, 8'h01, 8'h01, 8'h01, 8'h01, 8'h01, 8'h01, 8'h01, 8'h11, 8'h11, 8'h11, 8'h11, 8'h11, 8'h11, 8'h11, 8'h11, 8'h11, 8'h11, 8'h20, 8'h11, 8'h11, 8'h11, 8'h11, 8'h11, 8'h21, 8'h21, 8'h21, 8'h21, 8'h21, 8'h21, 8'h21, 8'h21, 8'h30, 8'h21, 8'h21, 8'h21, 8'h21, 8'h21, 8'h21, 8'h21, 8'h30, 8'h40, 8'h31, 8'h31, 8'h31, 8'h31, 8'h31, 8'h31, 8'h30, 8'h40, 8'h31, 8'h31, 8'h31, 8'h31, 8'h31, 8'h31, 8'h41, 8'h41, 8'h41, 8'h41, 8'h41, 8'h41, 8'h41, 8'h41, 8'h41, 8'h41, 8'h41, 8'h41, 8'h41, 8'h41, 8'h41, 8'h41, 8'h51, 8'h60, 8'h51, 8'h51, 8'h51, 8'h51, 8'h51, 8'h51, 8'h51, 8'h51, 8'h51, 8'h51, 8'h51, 8'h51, 8'h51, 8'h51, 8'h61, 8'h61, 8'h61, 8'h61, 8'h61, 8'h61, 8'h61, 8'h61, 8'h61, 8'h61, 8'h61, 8'h61, 8'h61, 8'h61, 8'h61, 8'h61, 8'h71, 8'h71, 8'h71, 8'h71, 8'h71, 8'h71, 8'h71, 8'h71, 8'h80, 8'h71, 8'h71, 8'h71, 8'h71, 8'h71, 8'h71, 8'h71, 8'h81, 8'h81, 8'h81, 8'h81, 8'h81, 8'h81, 8'h81, 8'h81, 8'h81, 8'h81, 8'h81, 8'h81, 8'h81, 8'h81, 8'h81, 8'h81, 8'h91, 8'h91, 8'h91, 8'h91, 8'h91, 8'h91, 8'h91, 8'h91, 8'h00, 8'h91, 8'h91, 8'h91, 8'h91, 8'h91, 8'h91, 8'h91, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'h01, 8'h01, 8'h10, 8'h01, 8'h01, 8'h01, 8'h01, 8'h01, 8'h01, 8'h01, 8'h01, 8'h01, 8'h01, 8'h01, 8'h01, 8'h01, 8'h11, 8'h11, 8'h11, 8'h11, 8'h11, 8'h11, 8'h11, 8'h11, 8'h11, 8'h11, 8'h20, 8'h11, 8'h11, 8'h11, 8'h11, 8'h11, 8'h21, 8'h21, 8'h21, 8'h21, 8'h21, 8'h21, 8'h21, 8'h21, 8'h30, 8'h21, 8'h21, 8'h21, 8'h21, 8'h21, 8'h21, 8'h21, 8'h30, 8'h70, 8'h31, 8'h31, 8'h31, 8'h31, 8'h31, 8'h31, 8'h30, 8'h70, 8'h31, 8'h31, 8'h31, 8'h31, 8'h31, 8'h31, 8'h41, 8'h41, 8'h41, 8'h41, 8'h41, 8'h41, 8'h41, 8'h41, 8'h50, 8'h41, 8'h41, 8'h41, 8'h41, 8'h41, 8'h41, 8'h41, 8'h51, 8'h51, 8'h51, 8'h51, 8'h51, 8'h51, 8'h51, 8'h51, 8'h51, 8'h51, 8'h51, 8'h51, 8'h51, 8'h51, 8'h51, 8'h51, 8'h61, 8'h61, 8'h61, 8'h61, 8'h61, 8'h61, 8'h61, 8'h61, 8'h00, 8'h61, 8'h61, 8'h61, 8'h61, 8'h61, 8'h61, 8'h61, 8'h71, 8'h71, 8'h71, 8'h71, 8'h71, 8'h71, 8'h71, 8'h71, 8'h71, 8'h71, 8'h71, 8'h71, 8'h71, 8'h71, 8'h71, 8'h71, 8'h81, 8'h90, 8'h81, 8'h81, 8'h81, 8'h81, 8'h81, 8'h81, 8'h81, 8'h81, 8'h81, 8'h81, 8'h81, 8'h81, 8'h81, 8'h81, 8'h91, 8'h91, 8'h91, 8'h91, 8'h91, 8'h91, 8'h91, 8'h91, 8'h91, 8'h91, 8'h91, 8'h91, 8'h91, 8'h91, 8'h91, 8'h91, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1, 8'ha1};
/*
	always_comb begin
		assign stream_state_update_mem_data = stream_state_update_mem[stream_state_update_mem_addr];
	end
*/
	
	always @(posedge clk)	begin

		ch_hash_cmd_intf_out.valid = 0;
		ch_tcp_inspect_out.valid = 0;
		ch_tcp_segment_out.valid = 0;

		wr_ch_tcp_inspect_data_flow = 0;
		wr_ch_hash_module = 0;
		
		if(~reset)		begin
			ch_eth_hdr_in_ready = 0;
			ch_ipv4_hdr_in_ready = 0;
			ch_tcp_hdr_in_ready = 0;
			ch_hash_ret_intf_in_ready = 0;
			
			ch_hash_cmd_intf_out.valid = 0;
			ch_tcp_inspect_out.valid = 0;
			ch_tcp_segment_out.valid = 0;

			tcp_reassembly_state = state_init;		
		end
		
		else if(tcp_reassembly_state == state_init)	begin
			ch_eth_hdr_in_ready = 1;
			tcp_reassembly_state = state_read_eth;
		end
			
		else if(tcp_reassembly_state == state_read_eth)		begin
			if(ch_eth_hdr_in.valid == 1)	begin	
				eth_hdr  = ch_eth_hdr_in.data;

				if(eth_hdr.eth_type == `ETH_TYPE_IPV4)	begin
					ch_eth_hdr_in_ready = 0;				
					ch_ipv4_hdr_in_ready = 1;
					tcp_reassembly_state = state_read_ipv4;
				end
			end
		end
		
		else if(tcp_reassembly_state == state_read_ipv4)	begin
			if(ch_ipv4_hdr_in.valid == 1)	begin
				ipv4_hdr = ch_ipv4_hdr_in.data;
				ch_ipv4_hdr_in_ready = 0;
			
				if( ipv4_hdr.ip_p == `IPV4_PROTO_TCP)	begin
					ch_tcp_hdr_in_ready = 1;
					tcp_reassembly_state = state_read_tcp;
				end

				else	begin
					ch_eth_hdr_in_ready = 1;
					tcp_reassembly_state = state_read_eth;
				end
			end
		end
		
		else if(tcp_reassembly_state == state_read_tcp) 	begin
			if(ch_tcp_hdr_in.valid == 1)	begin
				tcp_hdr  = ch_tcp_hdr_in.data;
				ch_tcp_hdr_in_ready = 0;	
				
				tcp_reassembly_state = state_read;
			end
		end

		else if (tcp_reassembly_state == state_read)	begin
			
			tcp_flags = tcp_hdr.th_flags;
			tcp_seg_len = ipv4_hdr.ip_len - (ipv4_hdr.ip_hl<<2) - (tcp_hdr.th_off<<2);
			dir = (ipv4_hdr.ip_src > ipv4_hdr.ip_dst);
			
			if(dir == 0)	begin // 1 -> 2	

				tcp_stream_hashkey.ip_1 	  = ipv4_hdr.ip_src;
				tcp_stream_hashkey.ip_2 	  = ipv4_hdr.ip_dst;
				tcp_stream_hashkey.tcp_port_1 = tcp_hdr.th_sport;
				tcp_stream_hashkey.tcp_port_2 = tcp_hdr.th_dport;
			end
			else	begin // 2 -> 1
	
				tcp_stream_hashkey.ip_1 	  = ipv4_hdr.ip_dst;
				tcp_stream_hashkey.ip_2 	  = ipv4_hdr.ip_src;
				tcp_stream_hashkey.tcp_port_1 = tcp_hdr.th_dport;
				tcp_stream_hashkey.tcp_port_2 = tcp_hdr.th_sport;
						
			end
			
			//find in hash table
			wr_ch_hash_module = 1;	hash_cmd = cmd_find; 
		
			tcp_reassembly_state = state_update;
		end	

		else if(tcp_reassembly_state == state_update)	begin
		
			if(hash_ret == error)	stream_state = closed;	//not found, need to insert new
			else	stream_state = stream_state_t'(tcp_stream_hash_data.stream_state);	//entry exisis, retrieve stream_state
			
			stream_state_prev = stream_state;
			
			//check flags and update state
			//stream_state_update_func(&stream_state, &tcp_flags, &dir, &err);

			stream_state_update_mem_addr[15:9] = 0;
			stream_state_update_mem_addr[8] = dir;
			stream_state_update_mem_addr[7:4] = stream_state;
			stream_state_update_mem_addr[3] = tcp_flags[4];	// `ACK_FLAG_MASK;
			stream_state_update_mem_addr[2:0] = tcp_flags[2:0];

			tcp_reassembly_state = state_update_1;
		end
		
		else if(tcp_reassembly_state == state_update_1)		begin
		
			//stream_state = stream_state_updated;
			stream_state = stream_state_t'(stream_state_update_mem_data[7:4]);
			err = stream_state_update_mem_data[0];

			if(err != 0) begin	
				
				//stream_state mismatch. report error		
				wr_ch_tcp_inspect_data_flow = 1; tcp_inspect_cmd = cmd_pass_through;
				tcp_reassembly_state = state_read_eth;
			end
			
			//valid flags for this stream_state
			else if(hash_ret == error)	begin
				
				//not found, need to insert new 			
				tcp_stream_hash_data.stream_state = stream_state;
				tcp_stream_hash_data.slot_dir_valid = 0;	//all invalid
				
				wr_ch_tcp_inspect_data_flow = 1; tcp_inspect_cmd = cmd_pass_through;
				
				//call hash module to insert. For now, assume that ret is successful
				wr_ch_hash_module = 1;	hash_cmd = cmd_insert;

				tcp_reassembly_state = state_read_eth;	
			end
			
			//entry exisis
			else if(stream_state == closed) 	begin
				
				//stream closed, delete entry
				tcp_stream_hash_data.stream_state = stream_state;

				wr_ch_tcp_inspect_data_flow = 1; tcp_inspect_cmd = cmd_pass_through;
				wr_ch_hash_module = 1;	hash_cmd = cmd_delete;				
				tcp_reassembly_state = state_read_eth;
			end
		
			else if( !((stream_state_prev == open) && (stream_state == open)) ) 	begin
				
				//only handshaking, no payload involved
				tcp_stream_hash_data.stream_state = stream_state;

				//update expected seq numbers
				if(stream_state == syn_ack)	begin
					if(dir==0)	tcp_stream_hash_data.seq_num_exp[0] = tcp_hdr.th_seq+1;
					else		tcp_stream_hash_data.seq_num_exp[1] = tcp_hdr.th_seq+1;
				end
				else if(stream_state == open)	begin
					if(dir==0)	tcp_stream_hash_data.seq_num_exp[0] = tcp_hdr.th_seq;
					else		tcp_stream_hash_data.seq_num_exp[1] = tcp_hdr.th_seq;					
				end

				wr_ch_tcp_inspect_data_flow = 1; tcp_inspect_cmd = cmd_pass_through;
				wr_ch_hash_module = 1;	hash_cmd = cmd_update;
				tcp_reassembly_state = state_read_eth;
			end
				
			//dir 1 -> 2
			else if(dir == 0)	begin
		
				if(tcp_hdr.th_seq == tcp_stream_hash_data.seq_num_exp[0])	begin
		
					//update expected sequence number
					tcp_stream_hash_data.seq_num_exp[0] += tcp_seg_len;
		
					//stream data through
					wr_ch_tcp_inspect_data_flow = 1; tcp_inspect_cmd = cmd_pass_through;
					tcp_reassembly_state = state_chk_slot_pkt_dir_0;
				end
				
				//out of order packet
				else begin
		
					//search for empty slot 
					
					slot = 8'hFF;
					
					if((tcp_stream_hash_data.slot_dir_valid & 8'h03)==8'h00 ) begin	//slot 0 empty
					
						slot=0; tcp_stream_hash_data.slot_dir_valid |= 8'h01;	//slot: 0, dir: 0, valid: 1
						tcp_stream_hash_data.seg_len_slot[0] = tcp_seg_len;
					end
					else if((tcp_stream_hash_data.slot_dir_valid & (8'h03<<2))==8'h00 )	begin	//slot 1 empty
					
						slot=1; tcp_stream_hash_data.slot_dir_valid |= (8'h01<<2);			//slot: 1, dir: 0, valid: 1
						tcp_stream_hash_data.seg_len_slot[1] = tcp_seg_len;
					end
					else if((tcp_stream_hash_data.slot_dir_valid & (8'h03<<4))==8'h00 )	begin	//slot 2 empty
		
						slot=2; tcp_stream_hash_data.slot_dir_valid |= (8'h01<<4);			//slot: 2, dir: 0, valid: 1
						tcp_stream_hash_data.seg_len_slot[2] = tcp_seg_len;
					end
					else if((tcp_stream_hash_data.slot_dir_valid & (8'h03<<6))==8'h00 )	begin	//slot 3 empty
		
						slot=3; tcp_stream_hash_data.slot_dir_valid |= (8'h01<<6);			//slot: 3, dir: 0, valid: 1
						tcp_stream_hash_data.seg_len_slot[3] = tcp_seg_len;
					end
					
					//write data to that slot		
					wr_ch_tcp_inspect_data_flow = 1; tcp_inspect_cmd = cmd_write_packet;

					//update hash entry
					wr_ch_hash_module = 1;	hash_cmd  = cmd_update;
					
					tcp_reassembly_state = state_read_eth;
				end
			end
				
			//dir 2 -> 1
			else if(dir == 1)	begin
				
				if(tcp_hdr.th_seq == tcp_stream_hash_data.seq_num_exp[1])	begin
		
					//update expected sequence number
					tcp_stream_hash_data.seq_num_exp[1] += tcp_seg_len;
		
					//stream data through
					wr_ch_tcp_inspect_data_flow = 1; tcp_inspect_cmd = cmd_pass_through;
					tcp_reassembly_state = state_chk_slot_pkt_dir_1;
				end
		
				//out of order packet
				else begin
		
					//search for empty slot 
					
					slot = 8'hFF;
					
					if((tcp_stream_hash_data.slot_dir_valid & 8'h03)==8'h00 ) begin	//slot 0 empty
					
						slot=0; tcp_stream_hash_data.slot_dir_valid |= 8'h03;	//slot: 0, dir: 1, valid: 1
						tcp_stream_hash_data.seg_len_slot[0] = tcp_seg_len;
					end
					else if((tcp_stream_hash_data.slot_dir_valid & (8'h03<<2))==8'h00 )	begin	//slot 1 empty
					
						slot=1; tcp_stream_hash_data.slot_dir_valid |= (8'h03<<2);			//slot: 1, dir: 1, valid: 1
						tcp_stream_hash_data.seg_len_slot[1] = tcp_seg_len;
					end
					else if((tcp_stream_hash_data.slot_dir_valid & (8'h03<<4))==8'h00 )	begin	//slot 2 empty
		
						slot=2; tcp_stream_hash_data.slot_dir_valid |= (8'h03<<4);			//slot: 2, dir: 1, valid: 1
						tcp_stream_hash_data.seg_len_slot[2] = tcp_seg_len;
					end
					else if((tcp_stream_hash_data.slot_dir_valid & (8'h03<<6))==8'h00 )	begin	//slot 3 empty
		
						slot=3; tcp_stream_hash_data.slot_dir_valid |= (8'h03<<6);			//slot: 3, dir: 1, valid: 1
						tcp_stream_hash_data.seg_len_slot[3] = tcp_seg_len;
					end
					
					//write data to that slot
					wr_ch_tcp_inspect_data_flow = 1; tcp_inspect_cmd = cmd_write_packet;
		
					//update hash entry
					wr_ch_hash_module = 1; hash_cmd = cmd_update;

					tcp_reassembly_state = state_read_eth;
				end
			end
		end
		
		else if(tcp_reassembly_state == state_chk_slot_pkt_dir_0)	begin
			//check if any of the packet slot is the next packet
		
			slot = 8'hFF;
		
			if( ((tcp_stream_hash_data.slot_dir_valid & (8'h03)) == 8'h01) && 	//slot: 0, dir: 0, valid: 1
				(tcp_stream_hash_data.seq_num_exp[0] == tcp_stream_hash_data.seq_num_slot[0]) ) begin							
		
				slot = 0;	tcp_stream_hash_data.slot_dir_valid &= (~8'h03); 	//invalidate slot 0
				tcp_seg_len = tcp_stream_hash_data.seg_len_slot[0];
			end
			else if( ((tcp_stream_hash_data.slot_dir_valid & (8'h03<<2)) == (8'h01<<2)) &&	//slot: 1, dir: 0, valid: 1
					 (tcp_stream_hash_data.seq_num_exp[0] == tcp_stream_hash_data.seq_num_slot[1]) )	begin
				
				slot = 1;	tcp_stream_hash_data.slot_dir_valid &= (~(8'h03<<2));			//invalidate slot 1
				tcp_seg_len = tcp_stream_hash_data.seg_len_slot[1];
			end
			else if( ((tcp_stream_hash_data.slot_dir_valid & (8'h03<<4)) == (8'h01<<4)) &&	//slot: 2, dir: 0, valid: 1
					 (tcp_stream_hash_data.seq_num_exp[0] == tcp_stream_hash_data.seq_num_slot[2]) )	begin
				
				slot = 2;	tcp_stream_hash_data.slot_dir_valid &= (~(8'h03<<4));			//invalidate slot 2
				tcp_seg_len = tcp_stream_hash_data.seg_len_slot[2];
			end
			else if( ((tcp_stream_hash_data.slot_dir_valid & (8'h03<<6)) == (8'h01<<6)) &&	//slot: 3, dir: 0, valid: 1
					 (tcp_stream_hash_data.seq_num_exp[0] == tcp_stream_hash_data.seq_num_slot[3]) )	begin
				
				slot = 3;	tcp_stream_hash_data.slot_dir_valid &= (~(8'h03<<6));			//invalidate slot 3
				tcp_seg_len = tcp_stream_hash_data.seg_len_slot[3];
			end 
			
			if(slot != 8'hFF)	begin
				//some valid slot found
				tcp_stream_hash_data.seq_num_exp[0] += tcp_seg_len;
		
				//stream data through
				wr_ch_tcp_inspect_data_flow = 1; tcp_inspect_cmd = cmd_read_packet;
				tcp_reassembly_state		 = state_chk_slot_pkt_dir_0;

			end

			else	begin

				wr_ch_hash_module = 1;	hash_cmd = cmd_update;				
				tcp_reassembly_state = state_read_eth;
			end
		end
		
		else if(tcp_reassembly_state == state_chk_slot_pkt_dir_1)	begin
			//check if any of the packet slot is the next packet
		
			slot = 8'hFF;
		
			if( ((tcp_stream_hash_data.slot_dir_valid & (8'h03)) == 8'h03) && 	//slot: 0, dir: 1, valid: 1
				(tcp_stream_hash_data.seq_num_exp[1] == tcp_stream_hash_data.seq_num_slot[0]) ) begin							
		
				slot = 0;	tcp_stream_hash_data.slot_dir_valid &= (~8'h03); 	//invalidate slot 0
				tcp_seg_len = tcp_stream_hash_data.seg_len_slot[0];
			end
			else if( ((tcp_stream_hash_data.slot_dir_valid & (8'h03<<2)) == (8'h03<<2)) &&	//slot: 1, dir: 1, valid: 1
					 (tcp_stream_hash_data.seq_num_exp[1] == tcp_stream_hash_data.seq_num_slot[1]) )	begin
				
				slot = 1;	tcp_stream_hash_data.slot_dir_valid &= (~(8'h03<<2));			//invalidate slot 1
				tcp_seg_len = tcp_stream_hash_data.seg_len_slot[1];
			end
			else if( ((tcp_stream_hash_data.slot_dir_valid & (8'h03<<4)) == (8'h03<<4)) &&	//slot: 2, dir: 1, valid: 1
					 (tcp_stream_hash_data.seq_num_exp[1] == tcp_stream_hash_data.seq_num_slot[2]) )	begin
				
				slot = 2;	tcp_stream_hash_data.slot_dir_valid &= (~(8'h03<<4));			//invalidate slot 2
				tcp_seg_len = tcp_stream_hash_data.seg_len_slot[2];
			end
			else if( ((tcp_stream_hash_data.slot_dir_valid & (8'h03<<6)) == (8'h03<<6)) &&	//slot: 3, dir: 1, valid: 1
					 (tcp_stream_hash_data.seq_num_exp[1] == tcp_stream_hash_data.seq_num_slot[3]) )	begin
				
				slot = 3;	tcp_stream_hash_data.slot_dir_valid &= (~(8'h03<<6));			//invalidate slot 3
				tcp_seg_len = tcp_stream_hash_data.seg_len_slot[3];
			end 
			
			if(slot != 8'hFF)	begin
				//some valid slot found
				tcp_stream_hash_data.seq_num_exp[1] += tcp_seg_len;
		
				//stream data through
				wr_ch_tcp_inspect_data_flow = 1; tcp_inspect_cmd = cmd_read_packet;
				tcp_reassembly_state = state_chk_slot_pkt_dir_1;	

			end
			else	begin
				wr_ch_hash_module = 1; hash_cmd = cmd_update;				
				tcp_reassembly_state = state_read_eth;
			end
		end	
	
		else if(tcp_reassembly_state == state_write_channels)	begin

			if( (wr_channel[2] == 1) && (ch_hash_cmd_intf_out_ready == 1) )	begin	//wr_ch_hash_module
				ch_hash_cmd_intf_out.data.cmd		= hash_cmd;
				ch_hash_cmd_intf_out.data.hashkey	= tcp_stream_hashkey;
				ch_hash_cmd_intf_out.data.hash_data	= tcp_stream_hash_data;
				ch_hash_cmd_intf_out.data.hash_node_addr = hash_node_addr;
				ch_hash_cmd_intf_out.valid = 1;	
				
				wr_channel[2] = 0;
				rd_ch_hash_module = 1;			
			end
		
			if( (wr_channel[1] == 1) && (ch_tcp_inspect_out_ready == 1) )	begin	//wr_ch_tcp_inspect_data_flow
				$display("STREAM_STATE: %s", stream_state_t'(tcp_stream_hash_data.stream_state));
				ch_tcp_inspect_out.data.tcp_inspect_cmd = tcp_inspect_cmd;
				ch_tcp_inspect_out.data.tcp_stream_addr = hash_node_addr;
				ch_tcp_inspect_out.data.slot = slot;
				ch_tcp_inspect_out.data.dir  = dir;
				ch_tcp_inspect_out.valid = 1;

				wr_channel[1] = 0;
			end

			if( (wr_channel[0] == 1) && (ch_tcp_segment_out_ready == 1)	) begin	//wr_ch_tcp_segment
				
				ch_tcp_segment_out.data.tcp_seg_len = tcp_seg_len;
				ch_tcp_segment_out.data.tcp_stream_hashkey = tcp_stream_hashkey;
				ch_tcp_segment_out.valid = 1;
				
				wr_channel[0] = 0;
			end

			if(wr_channel == 0) begin
				if(rd_ch_hash_module == 1)	begin
					tcp_reassembly_state = state_read_channels;
					ch_hash_ret_intf_in_ready = 1;
					rd_ch_hash_module = 0;
				end
				else 	begin
					tcp_reassembly_state = tcp_reassembly_state_return;
				end
			end
		end

		else if (tcp_reassembly_state == state_read_channels)	begin
			if(ch_hash_ret_intf_in.valid == 1) begin
				hash_node_addr 	  	= ch_hash_ret_intf_in.data.hash_node_addr;
				tcp_stream_hash_data 	= ch_hash_ret_intf_in.data.hash_data;
				hash_ret 		= ch_hash_ret_intf_in.data.hash_ret;
				
				ch_hash_ret_intf_in_ready = 0;
				tcp_reassembly_state = tcp_reassembly_state_return;
			end
		end

//if else block complete		
		
		if( (tcp_reassembly_state != state_write_channels) && (tcp_reassembly_state != state_read_channels) )	begin

			//{wr_ch_hash_module, wr_ch_tcp_inspect_data_flow, wr_ch_tcp_segment}
			if(wr_ch_hash_module == 1)	wr_channel[2] = 1;
			else	wr_channel[2] = 0;

			if(wr_ch_tcp_inspect_data_flow == 1)	wr_channel[1] = 1;
			else wr_channel[1] = 0;

			if( (wr_ch_tcp_inspect_data_flow == 1) && ((tcp_inspect_cmd == cmd_pass_through) || (tcp_inspect_cmd == cmd_read_packet)) ) wr_channel[0] = 1;
			else wr_channel[0] = 0;

			if(wr_channel != 0)	begin
				tcp_reassembly_state_return = tcp_reassembly_state;
				tcp_reassembly_state = state_write_channels;
			end
		end

		if(tcp_reassembly_state == state_read_eth)	ch_eth_hdr_in_ready = 1;
		
		//read memory
		stream_state_update_mem_data = stream_state_update_mem[stream_state_update_mem_addr];
		
	end	//always

endmodule

`endif
