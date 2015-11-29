`ifndef HASH_TB_SV
`define HASH_TB_SV

`include "hash/hash.vh"

import TYPEDEFS_P::*;
import HASH_TYPEDEFS_P::*;
import CHANNELS_P::*;

module hash_tb;

logic clk;
logic reset;

//read channel
ch_hash_cmd_intf_struct  ch_hash_cmd_intf_in;
logic ch_hash_cmd_intf_in_ready;

//write channel
ch_hash_ret_intf_struct  ch_hash_ret_intf_out;
logic	ch_hash_ret_intf_out_ready;
	
hash	hash_u0
(
.clk,
.reset,

//read channel
.ch_hash_cmd_intf_in,
.ch_hash_cmd_intf_in_ready,

//write channel
.ch_hash_ret_intf_out,
.ch_hash_ret_intf_out_ready
);

typedef enum
{
	s_start,
	s_cmd_find,
	s_cmd_insert,
	s_cmd_delete,
	s_cmd_update,
	s_ret,
	s_stop
} state_t;
state_t state_in;

typedef enum
{
	insert_1,
	insert_find_1,
	delete_1,
	delete_find_1,

	insert_2,
	insert_find_2,
	delete_2,
	delete_find_2
	
}	phase_t;
phase_t phase;

parameter NUM_TEST_CASES = 10;

hashkey_t hashkey[NUM_TEST_CASES];
hash_data_t hash_data[NUM_TEST_CASES];
uint16_t tmp;
uint8_t cnt;
hash_cmd_t hash_cmd_curr;

function uint32_t hash_func;
	input hashkey_t tcp_stream_hashkey;
	begin
		hash_func  = (tcp_stream_hashkey.ip_1 ^ tcp_stream_hashkey.ip_2 ^	tcp_stream_hashkey.tcp_port_1 ^ tcp_stream_hashkey.tcp_port_2);
	end
endfunction
	
initial begin
	tmp = 16'h55;	//random
	for(uint8_t i=0; i<NUM_TEST_CASES; i++)	begin
			
		hashkey[i].ip_1 = ++tmp;
		hashkey[i].ip_2 = ++tmp;
		hashkey[i].tcp_port_1 = ++tmp;
		hashkey[i].tcp_port_2 = ++tmp;

		hash_data[i].stream_state = i;
		$display("Test case: %d, hash_value: %u", i, (hash_func(hashkey[i])&(`HASH_TBL_NUM_ROWS-1)) );
		tmp+=7;
	end
end	
initial begin	
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
	ch_hash_cmd_intf_in.valid = 0;
	
	if(~reset) begin
		state_in = s_start;
		phase = insert_1;
		
		cnt = 0;
		ch_hash_ret_intf_out_ready = 1;
		ch_hash_cmd_intf_in.valid = 0;
	end
	
	else if (state_in == s_start)	begin
		state_in = s_cmd_find;
	end

	else if (state_in == s_cmd_find)	begin
		if(ch_hash_cmd_intf_in_ready == 1)	begin
			ch_hash_cmd_intf_in.data.cmd = cmd_find;
			ch_hash_cmd_intf_in.data.hashkey = hashkey[cnt];
			ch_hash_cmd_intf_in.data.hash_data = hash_data[cnt];
			
			ch_hash_cmd_intf_in.valid = 1;
			
			state_in = s_ret;
			ch_hash_ret_intf_out_ready = 1;
			hash_cmd_curr = cmd_find;
		end
	end

	else if (state_in == s_cmd_insert)	begin
		if(ch_hash_cmd_intf_in_ready == 1)	begin
			ch_hash_cmd_intf_in.data.cmd = cmd_insert;
			ch_hash_cmd_intf_in.valid = 1;
			
			state_in = s_ret;
			ch_hash_ret_intf_out_ready = 1;
			hash_cmd_curr = cmd_insert;
		end
	end

	else if (state_in == s_cmd_delete)	begin
		if(ch_hash_cmd_intf_in_ready == 1)	begin
			ch_hash_cmd_intf_in.data.cmd = cmd_delete;
			ch_hash_cmd_intf_in.data.hash_node_addr = ch_hash_ret_intf_out.data.hash_node_addr;
			ch_hash_cmd_intf_in.valid = 1;
			
			state_in = s_ret;
			ch_hash_ret_intf_out_ready = 1;
			hash_cmd_curr = cmd_delete;
		end
	end

	else if (state_in == s_cmd_update)	begin
	end
	
	else if (state_in == s_ret)	begin
		if(ch_hash_ret_intf_out.valid == 1)	begin
		
			if(hash_cmd_curr == cmd_find)	begin
				if(ch_hash_ret_intf_out.data.hash_ret != found)	begin
					$display("Test case: %d Find Error!!!", cnt);
				end
				else	begin
					$display("Test case found: %d, hash_node_addr = %u, hash_data = %d", cnt, 
						ch_hash_ret_intf_out.data.hash_node_addr, ch_hash_ret_intf_out.data.hash_data.stream_state);
				end
				
				if( (phase == insert_1) || (phase == insert_2) )		begin
					if(ch_hash_ret_intf_out.data.hash_ret != found)		state_in = s_cmd_insert;
					else begin
						cnt++;
						state_in = s_cmd_find;
					end
				end
				else if( (phase == delete_1) || (phase == delete_2) )	begin
					if(ch_hash_ret_intf_out.data.hash_ret == found)		state_in = s_cmd_delete;
					else begin
						cnt++;
						state_in = s_cmd_find;
					end
				end
				else if( (phase == insert_find_1) || (phase == delete_find_1) || (phase == insert_find_2) || (phase == delete_find_2) )	 begin
					state_in = s_cmd_find;
					cnt++;
				end
				
				if(cnt == NUM_TEST_CASES)	begin
					cnt = 0;
					if(phase == delete_find_2)	state_in = s_stop;
					else phase = phase_t'((uint8_t'(phase))+1);	//phase++;
					$display("\n");
				end
			end
			
			else if(hash_cmd_curr == cmd_insert)	begin
				if(ch_hash_ret_intf_out.data.hash_ret != inserted)	begin
					$display("Test case: %d Insert Error!!!", cnt);
				end
				else	begin
					$display("Test case inserted: %d, hash_node_addr = %u, hash_data = %d", cnt, 
						ch_hash_ret_intf_out.data.hash_node_addr, ch_hash_ret_intf_out.data.hash_data.stream_state);
				end
				state_in = s_cmd_find;
				++cnt;
				if(cnt == NUM_TEST_CASES)	begin
					cnt = 0;
					phase = phase_t'((uint8_t'(phase))+1);	//phase++;
					$display("\n");
				end
			end
			
			else if(hash_cmd_curr == cmd_delete)	begin
				if(ch_hash_ret_intf_out.data.hash_ret != deleted)	begin
					$display("Test case: %d Delete Error!!!", cnt);
				end
				else	begin
					$display("Test case deleted: %d, hash_node_addr = %u, hash_data = %d", cnt, 
						ch_hash_ret_intf_out.data.hash_node_addr, ch_hash_ret_intf_out.data.hash_data.stream_state);
				end
				state_in = s_cmd_find;
				if(phase == delete_2)	cnt++;
				else if(phase == delete_1)	cnt+=2;
				
				if(cnt == NUM_TEST_CASES)	begin
					cnt = 0;
					phase = phase_t'((uint8_t'(phase))+1);	//phase++;
					$display("\n");
				end
			end
			
			ch_hash_ret_intf_out_ready = 0;
		end
	end
	
	else if(state_in == s_stop)	begin
		state_in = state_in;
	end
end //always
	
endmodule

`endif
