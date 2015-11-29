`ifndef HASH_SV
`define HASH_SV

`include "hash/hash.vh"

import TYPEDEFS_P::*;
import HASH_TYPEDEFS_P::*;
import CHANNELS_P::*;

module hash
(
	input logic clk,
	input logic reset,
	
	//read channel
	input ch_hash_cmd_intf_struct  ch_hash_cmd_intf_in,
	output logic ch_hash_cmd_intf_in_ready,
	
	//write channel
	output ch_hash_ret_intf_struct  ch_hash_ret_intf_out,
	input logic	ch_hash_ret_intf_out_ready
);

	hash_node_struct	hash_node_mem	[`HASH_TBL_MEM_SIZE];		// 48*1024 = 48 KB
	hash_node_addr_t	hash_row_hdr_mem[`HASH_TBL_NUM_ROWS];		// 2*256 = 512
	avail_mem_addr_t	avail_mem_stack [`HASH_TBL_MEM_SIZE];		// 2*1024 = 2 KB
	avail_mem_addr_t 	tos;

	initial begin
		avail_mem_addr_t i;
		hash_row_hdr_addr_t j;
		
		//initialize avail mem stack
		for(i=0; i<`HASH_TBL_MEM_SIZE; i++) 
		begin
			avail_mem_stack[i] = i;
		end	

		//initialize all row header addresses as invalid
		for(j = 0; j<`HASH_TBL_NUM_ROWS; j++) 
		begin
			hash_row_hdr_mem[j] = `HASH_TBL_MEM_INVALID_ADDR;
		end
		
		//initialize tos
		tos = `HASH_TBL_MEM_SIZE-1;	//top of stack
	end	//end initial

	hash_node_addr_t 	hash_node_addr, hash_node_addr_curr, hash_node_addr_prev, hash_node_addr_next;
	hash_row_hdr_addr_t hash_row_hdr_addr;
	hash_node_struct 	hash_node, hash_node_prev, hash_node_curr;
	hash_node_addr_t	hash_row_hdr;
	
	hash_cmd_t 			cmd_in; 			 
	hashkey_t 			hashkey_in; 		 
	hash_data_t 		hash_data_in; 	 
	hash_node_addr_t	hash_node_addr_in;
	
	hash_node_addr_t 	hash_node_addr_out;
	hash_data_t			hash_data_out;
	hash_ret_t			hash_ret_out;

	hash_cmd_intf_t  	hash_cmd_intf;
	hash_ret_intf_t 	hash_ret_intf;
	
	hash_state_t hash_state;

	bool hashkey_match;
	bool update_node_next, update_node_prev, update_row_hdr;

	hash_node_addr_t	hash_mem_rd_addr, hash_mem_wr_addr;
	hash_node_struct	hash_mem_rd_data, hash_mem_wr_data;
	bool hash_mem_we;

	hash_row_hdr_addr_t	hash_row_hdr_mem_rd_addr, hash_row_hdr_mem_wr_addr;
	hash_node_addr_t	hash_row_hdr_mem_rd_data, hash_row_hdr_mem_wr_data;
	bool hash_row_hdr_mem_we;

	avail_mem_addr_t	avail_mem_stack_rd_addr, avail_mem_stack_wr_addr;
	avail_mem_addr_t	avail_mem_stack_rd_data, avail_mem_stack_wr_data;
	bool avail_mem_stack_we;

	//uint8_t find_iter;

	function uint32_t hash_func;
		input hashkey_t tcp_stream_hashkey;
		begin
			hash_func  = (tcp_stream_hashkey.ip_1 ^ tcp_stream_hashkey.ip_2 ^	tcp_stream_hashkey.tcp_port_1 ^ tcp_stream_hashkey.tcp_port_2);
		end
	endfunction
	
	function bool hashkey_comp_func;
		input hashkey_t tcp_stream_hashkey1, tcp_stream_hashkey2;
		begin
			hashkey_comp_func  = ((tcp_stream_hashkey1.ip_1 == tcp_stream_hashkey2.ip_1) & (tcp_stream_hashkey1.ip_2 == tcp_stream_hashkey2.ip_2) & 
				(tcp_stream_hashkey1.tcp_port_1 == tcp_stream_hashkey2.tcp_port_1) & (tcp_stream_hashkey1.tcp_port_2 == tcp_stream_hashkey2.tcp_port_2));
		end
	endfunction
	
	always @(posedge clk)	begin
		
		hash_mem_we = 0;
		hash_row_hdr_mem_we = 0;
		avail_mem_stack_we = 0;
		
		if(~reset)	begin
			ch_hash_ret_intf_out.valid = 0;
			ch_hash_cmd_intf_in_ready = 0;
			hash_state = hash_state_init;
		end
		
		else if(hash_state == hash_state_init)	begin
			ch_hash_cmd_intf_in_ready = 1;
			hash_state = hash_state_cmd;
		end

		else if(hash_state == hash_state_cmd)	begin
			ch_hash_ret_intf_out.valid = 0;
			if(ch_hash_cmd_intf_in.valid == 1)	begin				
				hash_cmd_intf = ch_hash_cmd_intf_in.data;
				ch_hash_cmd_intf_in_ready = 0;
				
				cmd_in 		  = hash_cmd_intf.cmd;
				hashkey_in 	  = hash_cmd_intf.hashkey; 
				hash_data_in 	  = hash_cmd_intf.hash_data;
				hash_node_addr_in = hash_cmd_intf.hash_node_addr;

				if(cmd_in == cmd_insert)		begin
					avail_mem_stack_rd_addr = tos;
					hash_state = hash_state_insert_0;
				end
				else if(cmd_in == cmd_delete)	begin
					
					hash_row_hdr_addr = hash_func(hashkey_in)&(`HASH_TBL_NUM_ROWS-1);
					hash_mem_rd_addr = hash_node_addr_in;								
					hash_state = hash_state_delete_0;
				end
				
				else if(cmd_in == cmd_find)		begin
					hash_row_hdr_addr   = hash_func(hashkey_in)&(`HASH_TBL_NUM_ROWS-1);
					hash_row_hdr_mem_rd_addr = hash_row_hdr_addr;
					hash_state = hash_state_find_0;
					//find_iter = 0;
				end
				
				else if(cmd_in == cmd_update)	begin
					
					hash_mem_rd_addr = hash_node_addr_in;				
					hash_state = hash_state_update_0;
				end
			end
		end

		//insert		
		else if(hash_state == hash_state_insert_0)	//input: hashkey
		begin

			hash_node_addr	= avail_mem_stack_rd_data;
			tos--;
			
			//need to insert after "hash_node_addr_prev"
			//"hash_node" is the current node at addr "hash_node_addr_prev" if valid
			//hash_node already has the node data, that was populated by the find cmd earlier

			hash_node_curr.hashkey	= hashkey_in;
			hash_node_curr.hash_data = hash_data_in;
			hash_node_curr.hash_addr_prev = hash_node_addr_prev;
			hash_node_curr.hash_addr_next = `HASH_TBL_MEM_INVALID_ADDR;

			if(hash_node_addr_prev != `HASH_TBL_MEM_INVALID_ADDR)	begin	//valid
				hash_node.hash_addr_next = hash_node_addr;

				//update hash mem
				hash_mem_wr_addr = hash_node_addr_prev;
				hash_mem_wr_data = hash_node;
				hash_mem_we = 1;

			end
			else	begin //update the row hdr entry
	
				hash_row_hdr_mem_wr_addr = hash_func(hashkey_in)&(`HASH_TBL_NUM_ROWS-1);
				hash_row_hdr_mem_wr_data = hash_node_addr;
				hash_row_hdr_mem_we = 1;
			end
			
			hash_state = hash_state_insert_1;
			
		end
		else if (hash_state == hash_state_insert_1)
		begin
				
			hash_mem_wr_addr = hash_node_addr;
			hash_mem_wr_data = hash_node_curr;
			hash_mem_we = 1;	
			
			hash_node_addr_out = hash_node_addr;
			hash_data_out = hash_node_curr.hash_data;
			hash_ret_out  = inserted;

			hash_state = hash_state_write_output;
		end

		else if (hash_state == hash_state_delete_0)	//input: hash_node_addr_in, hashkey
		begin
			hash_node = hash_mem_rd_data;
			
			if( (hash_node.hash_addr_prev == `HASH_TBL_MEM_INVALID_ADDR) && (hash_node.hash_addr_next == `HASH_TBL_MEM_INVALID_ADDR) )
				
			begin	//single element
				hash_row_hdr = `HASH_TBL_MEM_INVALID_ADDR;
				update_row_hdr = 1;
				update_node_next = 0; update_node_prev = 0;
			end
			else if (hash_node.hash_addr_prev == `HASH_TBL_MEM_INVALID_ADDR)
				
			begin	//remove head node
				hash_row_hdr = hash_node.hash_addr_next;
				update_row_hdr = 1;
				
				hash_node_addr_next = hash_node.hash_addr_next;
				hash_node_addr_prev = `HASH_TBL_MEM_INVALID_ADDR;
				update_node_next = 1; update_node_prev = 0;
			end
			
			else if (hash_node.hash_addr_next == `HASH_TBL_MEM_INVALID_ADDR)

			begin	//remove tail node
				update_row_hdr = 0;

				hash_node_addr_prev = hash_node.hash_addr_prev;
				hash_node_addr_next = `HASH_TBL_MEM_INVALID_ADDR;				
				update_node_next = 0; update_node_prev = 1;
			end
			
			else	begin
				update_row_hdr = 0;
				hash_node_addr_prev = hash_node.hash_addr_prev;
				hash_node_addr_next = hash_node.hash_addr_next;
				update_node_next = 1; update_node_prev = 1;				
			end
			
			if(update_row_hdr)	begin
				
				hash_row_hdr_mem_wr_addr = hash_row_hdr_addr;
				hash_row_hdr_mem_wr_data = hash_row_hdr;
				hash_row_hdr_mem_we = 1;
			end
			
			if(update_node_prev)		hash_state = hash_state_delete_1;
			else if(update_node_next)	hash_state = hash_state_delete_3;
			else hash_state = hash_state_delete_5;
			
		end
		else if (hash_state == hash_state_delete_1)	begin
			hash_mem_rd_addr = hash_node_addr_prev;
			hash_state = hash_state_delete_2;
		end
		
		else if (hash_state == hash_state_delete_2)	//update_node_prev
		begin
			
			hash_mem_rd_data.hash_addr_next = hash_node_addr_next;			
			hash_mem_wr_addr = hash_node_addr_prev;
			hash_mem_wr_data = hash_mem_rd_data;
			hash_mem_we = 1;
		
			if(update_node_next)	hash_state = hash_state_delete_3;
			else hash_state = hash_state_delete_5;
		end
		
		else if (hash_state == hash_state_delete_3)	//update_node_next
		begin
			hash_mem_rd_addr = hash_node_addr_next;
			hash_state = hash_state_delete_4;
		end
		
		else if (hash_state == hash_state_delete_4)	
		begin
			hash_mem_rd_data.hash_addr_prev = hash_node_addr_prev;
			hash_mem_wr_addr = hash_node_addr_next;
			hash_mem_wr_data = hash_mem_rd_data;
			hash_mem_we = 1;
			
			hash_state = hash_state_delete_5;
		end

		else if (hash_state == hash_state_delete_5)
		begin
			tos++;
			avail_mem_stack_wr_addr = tos;
			avail_mem_stack_wr_data = hash_node_addr_in;
			avail_mem_stack_we = 1;
			
			hash_ret_out  = deleted;
			hash_state = hash_state_write_output;
		end
		
		else if (hash_state == hash_state_find_0) //input: hashkey
		begin				
			hash_node_addr_curr = hash_row_hdr_mem_rd_data;
			hash_node_addr_prev = hash_node_addr_curr;
			hashkey_match = 0;
			if(hash_node_addr_curr == `HASH_TBL_MEM_INVALID_ADDR)	hash_state = hash_state_find_3;		
			else begin
				//find_iter++;
				hash_mem_rd_addr = hash_node_addr_curr;				
				hash_state = hash_state_find_1;
			end
		end
		
		else if (hash_state == hash_state_find_1)
		begin
			hash_node = hash_mem_rd_data;
			hashkey_match = hashkey_comp_func(hashkey_in, hash_node.hashkey);
			hash_state = hash_state_find_2;
		end
		
		else if (hash_state == hash_state_find_2)
		begin
			if(hashkey_match == 0)	begin
				hash_node_addr_prev = hash_node_addr_curr;
				hash_node_addr_curr = hash_node.hash_addr_next;
			end
			if( (hash_node_addr_curr == `HASH_TBL_MEM_INVALID_ADDR) || (hashkey_match == 1) )	begin
				hash_state = hash_state_find_3;		
			end
			else begin
				//find_iter++;
				hash_mem_rd_addr = hash_node_addr_curr;
				hash_state = hash_state_find_1;	
			end
		end
		
		else if (hash_state == hash_state_find_3)
		begin
			if(hashkey_match == 1)	//found
			begin
				hash_node_addr_out = hash_node_addr_curr;
				hash_data_out = hash_node.hash_data;
				hash_ret_out  = found;
			end
			else begin
				hash_ret_out  = error;
			end
			//$display("find iter: %d", find_iter);
			hash_state = hash_state_write_output;
		end

		else if (hash_state == hash_state_update_0) //input: hash_mem_addr_in, hash_data
		begin
			hash_node = hash_mem_rd_data;
			hash_node.hash_data = hash_data_in;

			hash_mem_wr_addr = hash_node_addr_in;
			hash_mem_wr_data = hash_node;
			hash_mem_we = 1;

			hash_ret_out = success;
			hash_state = hash_state_write_output;
		end
		
		else if (hash_state == hash_state_write_output) begin
		
			if(ch_hash_ret_intf_out_ready == 1)	begin
				hash_ret_intf.hash_node_addr = hash_node_addr_out;
				hash_ret_intf.hash_data		 = hash_data_out;
				hash_ret_intf.hash_ret		 = hash_ret_out;
				
				ch_hash_ret_intf_out.valid = 1;
				ch_hash_ret_intf_out.data = hash_ret_intf;
				
				ch_hash_cmd_intf_in_ready = 1;
				hash_state = hash_state_cmd;	
			end
		end
		
		hash_mem_rd_data = hash_node_mem[hash_mem_rd_addr];
		hash_row_hdr_mem_rd_data = hash_row_hdr_mem[hash_row_hdr_mem_rd_addr];	
		avail_mem_stack_rd_data = avail_mem_stack[avail_mem_stack_rd_addr];		
		
		if(hash_mem_we)	hash_node_mem[hash_mem_wr_addr] = hash_mem_wr_data;		
		if(hash_row_hdr_mem_we)	hash_row_hdr_mem[hash_row_hdr_mem_wr_addr] = hash_row_hdr_mem_wr_data;	
		if(avail_mem_stack_we)	avail_mem_stack[avail_mem_stack_wr_addr] = avail_mem_stack_wr_data;		

	end	//always
	
endmodule

`endif 
