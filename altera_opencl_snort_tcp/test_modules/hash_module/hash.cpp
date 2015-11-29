#ifndef HASH_CL
#define HASH_CL

#include <stdio.h>

#include "typedefs.h"
#include "protocols.h"
//#include "read_eth_mac.h"
//#include "parser.h"
#include "tcp_reassembly.h"
#include "hash.h"


hash_node_struct	hash_node_mem	[HASH_TBL_MEM_SIZE];		// 48*1024 = 48 KB
hash_node_addr_t	hash_row_hdr_mem[HASH_TBL_NUM_ROWS];		// 2*256 = 512
avail_mem_addr_t	avail_mem_stack [HASH_TBL_MEM_SIZE];		// 2*1024 = 2 KB
avail_mem_addr_t 	tos;

uint32_t hash_func (tcp_stream_hashkey_t tcp_stream_hashkey);
bool hashkey_comp_func (tcp_stream_hashkey_t tcp_stream_hashkey1, tcp_stream_hashkey_t tcp_stream_hashkey2);

hash_intf_out_t hash_module(hash_intf_in_t hash_intf_in)
{

	static hash_node_addr_t hash_node_addr_prev;
	
	hash_node_addr_t 	hash_node_addr, hash_node_addr_curr, hash_node_addr_next;
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

	hash_intf_out_t 	hash_intf_out;
	
	hash_state_t hash_state;

	hash_state = hash_state_cmd;
	for(;;)
	{
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
		
		hash_mem_we = 0;
		hash_row_hdr_mem_we = 0;
		avail_mem_stack_we = 0;

		hash_mem_rd_addr = 0;
		hash_row_hdr_mem_rd_addr = 0;
		avail_mem_stack_rd_addr = 0;

		printf("\nhash state = %s", hash_state_names[hash_state]);	fflush(stdout);
		
		if(hash_state == hash_state_cmd)	{
			//hash_intf_in = read_channel_altera(ch_hash_intf_in);
		
			cmd_in 		  = hash_intf_in.cmd;
			hashkey_in 	  = hash_intf_in.hashkey; 
			hash_data_in 	  = hash_intf_in.hash_data;
			hash_node_addr_in = hash_intf_in.hash_node_addr;

			if(cmd_in == cmd_insert)		{
				//hash_node_addr	= avail_mem_stack[tos];
#ifdef EMUL
				if(tos == AVAIL_MEM_ADDR_EMPTY)	printf("\n Out of memory for hash table");
#endif				
				avail_mem_stack_rd_addr = tos;
				hash_state = hash_state_insert_0;
			}
			else if(cmd_in == cmd_delete)	{
				
				hash_row_hdr_addr 	= hash_func(hashkey_in)&(HASH_TBL_NUM_ROWS-1);				
				//hash_node = hash_node_mem[hash_node_addr_in];
				hash_mem_rd_addr = hash_node_addr_in;								
				hash_state = hash_state_delete_0;
			}
			
			else if(cmd_in == cmd_find)		{
				hash_row_hdr_addr   = hash_func(hashkey_in)&(HASH_TBL_NUM_ROWS-1);
				//hash_node_addr_curr = hash_row_hdr_mem[hash_row_hdr_addr];
				hash_row_hdr_mem_rd_addr = hash_row_hdr_addr;
				hash_state = hash_state_find_0;
			}
			
			else if(cmd_in == cmd_update)	{
				
				//hash_node = hash_node_mem[hash_node_addr_in];
				hash_mem_rd_addr = hash_node_addr_in;				
				hash_state = hash_state_update_0;
			}
		}

		//insert		
		else if(hash_state == hash_state_insert_0)	//input: hashkey
		{

			hash_node_addr	= avail_mem_stack_rd_data;
			tos--;
			
			//need to insert after "hash_node_addr_prev"
			//"hash_node" is the current node at addr "hash_node_addr_prev" if valid
			//hash_node already has the node data, that was populated by the find cmd earlier

			hash_node_curr.hashkey	= hashkey_in;
			hash_node_curr.hash_data = hash_data_in;
			hash_node_curr.hash_addr_prev = hash_node_addr_prev;
			hash_node_curr.hash_addr_next = HASH_TBL_MEM_INVALID_ADDR;

			if(hash_node_addr_prev != HASH_TBL_MEM_INVALID_ADDR)	{	//valid
				hash_node.hash_addr_next = hash_node_addr;

				//update hash mem
				//hash_node_mem[hash_node_addr_prev] = hash_node;
				hash_mem_wr_addr = hash_node_addr_prev;
				hash_mem_wr_data = hash_node;
				hash_mem_we = 1;

			}
			else	{	//update the row hdr entry
			
				//hash_row_hdr_addr = hash_func(hashkey_in)&(HASH_TBL_NUM_ROWS-1);
				//hash_row_hdr_mem[hash_row_hdr_addr] = hash_node_addr;

				hash_row_hdr_mem_rd_addr = hash_func(hashkey_in)&(HASH_TBL_NUM_ROWS-1);
				hash_row_hdr_mem_rd_data = hash_node_addr;
				hash_row_hdr_mem_we = 1;
			}

			hash_state = hash_state_insert_1;
			
		}
		else if (hash_state == hash_state_insert_1)
		{
			//hash_node_mem[hash_node_addr] = hash_node_curr;			
			hash_mem_wr_addr = hash_node_addr;
			hash_mem_wr_data = hash_node_curr;
			hash_mem_we = 1;	
			
			hash_node_addr_out = hash_node_addr;
			hash_data_out = hash_node_curr.hash_data;
			hash_ret_out  = inserted;

			hash_state = hash_state_write_output;
		}

		else if (hash_state == hash_state_delete_0)	//input: hash_node_addr_in, hashkey
		{
			hash_node = hash_mem_rd_data;
			if( (hash_node.hash_addr_prev == HASH_TBL_MEM_INVALID_ADDR) && (hash_node.hash_addr_next == HASH_TBL_MEM_INVALID_ADDR) )
				
			{	//single element
				hash_row_hdr = HASH_TBL_MEM_INVALID_ADDR;
				update_row_hdr = 1;
				update_node_next = 0; update_node_prev = 0;
			}
			else if (hash_node.hash_addr_prev == HASH_TBL_MEM_INVALID_ADDR)
				
			{	//remove head node
				hash_row_hdr = hash_node.hash_addr_next;
				update_row_hdr = 1;
				
				hash_node_addr_next = hash_node.hash_addr_next;
				hash_node_addr_prev = HASH_TBL_MEM_INVALID_ADDR;
				update_node_next = 1; update_node_prev = 0;
			}
			
			else if (hash_node.hash_addr_next == HASH_TBL_MEM_INVALID_ADDR)

			{	//remove tail node
				update_row_hdr = 0;

				hash_node_addr_prev = hash_node.hash_addr_prev;
				hash_node_addr_next = HASH_TBL_MEM_INVALID_ADDR;				
				update_node_next = 0; update_node_prev = 1;
			}
			
			else 
			{
				update_row_hdr = 0;
				hash_node_addr_prev = hash_node.hash_addr_prev;
				hash_node_addr_next = hash_node.hash_addr_next;
				update_node_next = 1; update_node_prev = 1;
				
			}
			tos++;
			
			if(update_row_hdr)	{
				
				//hash_row_hdr_mem[hash_row_hdr_addr] = hash_row_hdr;
				hash_row_hdr_mem_wr_addr = hash_row_hdr_addr;
				hash_row_hdr_mem_wr_data = hash_row_hdr;
				hash_row_hdr_mem_we = 1;
			}
			
			if(update_node_prev)	{
				hash_mem_rd_addr = hash_node_addr_prev;
				hash_state = hash_state_delete_1;
			}
			else if(update_node_next)	hash_state = hash_state_delete_2;
			else hash_state = hash_state_delete_3;
			
		}
		else if (hash_state == hash_state_delete_1)	//update_node_prev
		{
			
			hash_mem_rd_data.hash_addr_next = hash_node_addr_next;
			
			//hash_node_mem[hash_node_addr_prev].hash_addr_next = hash_node_addr_next;
			hash_mem_wr_addr = hash_node_addr_prev;
			hash_mem_wr_data = hash_mem_rd_data;
			hash_mem_we = 1;
		
			if(update_node_next)	hash_state = hash_state_delete_2;
			else hash_state = hash_state_delete_3;
		}
		else if (hash_state == hash_state_delete_2)	//update_node_next
		{
			hash_mem_rd_addr = hash_node_addr_next;
			hash_state = hash_state_delete_3;
		}

		else if (hash_state == hash_state_delete_3)
		{			
			if(update_node_next)		{
				
				//hash_node_mem[hash_node_addr_next].hash_addr_prev = hash_node_addr_prev;
				hash_mem_rd_data.hash_addr_prev = hash_node_addr_prev;
				
				hash_mem_wr_addr = hash_node_addr_next;
				hash_mem_wr_data = hash_mem_rd_data;
				hash_mem_we = 1;				

			}
			
			//avail_mem_stack[tos] = hash_node_addr_in;
			avail_mem_stack_wr_addr = tos;
			avail_mem_stack_wr_data = hash_node_addr_in;
			avail_mem_stack_we = 1;
			
			hash_ret_out  = deleted;
			hash_state = hash_state_write_output;
		}
		
		else if (hash_state == hash_state_find_0) //input: hashkey
		{				
			hash_node_addr_curr = hash_row_hdr_mem_rd_data;
			hash_node_addr_prev = hash_node_addr_curr;
			hashkey_match = 0;
			if(hash_node_addr_curr == HASH_TBL_MEM_INVALID_ADDR)	hash_state = hash_state_find_3;		
			else {
				
				//hash_node = hash_node_mem[hash_node_addr_curr];
				hash_mem_rd_addr = hash_node_addr_curr;				
				hash_state = hash_state_find_1;
			}
		}
		
		else if (hash_state == hash_state_find_1)
		{
			hash_node = hash_mem_rd_data;
			hashkey_match = hashkey_comp_func(hashkey_in, hash_node.hashkey);
			hash_state = hash_state_find_2;
		}
		
		else if (hash_state == hash_state_find_2)
		{
			if(hashkey_match == 0)	{
				hash_node_addr_prev = hash_node_addr_curr;
				hash_node_addr_curr = hash_node.hash_addr_next;
			}
			if( (hash_node_addr_curr == HASH_TBL_MEM_INVALID_ADDR) || (hashkey_match == 1) )	
				hash_state = hash_state_find_3;		
			else {
				hash_mem_rd_addr = hash_node_addr_curr;
				hash_state = hash_state_find_1;	
			}
		}
		
		else if (hash_state == hash_state_find_3)
		{
			if(hashkey_match == 1)	//found
			{
				hash_node_addr_out = hash_node_addr_curr;
				hash_data_out = hash_node.hash_data;
				hash_ret_out  = found;
			}
			else {
				hash_ret_out  = error;
			}
			hash_state = hash_state_write_output;
		}

		else if (hash_state == hash_state_update_0) //input: hash_mem_addr_in, hash_data
		{
			hash_node = hash_mem_rd_data;
			hash_node.hash_data = hash_data_in;
			
			//hash_node_mem[hash_node_addr_in] = hash_node;
			hash_mem_wr_addr = hash_node_addr_in;
			hash_mem_wr_data = hash_node;
			hash_mem_we = 1;

			hash_ret_out = success;
			hash_state = hash_state_write_output;
		}
		
		else if (hash_state == hash_state_write_output) {
			hash_intf_out.hash_node_addr = hash_node_addr_out;
			hash_intf_out.hash_data		 = hash_data_out;
			hash_intf_out.hash_ret		 = hash_ret_out;
			
			//write_channel_altera(ch_hash_intf_out, hash_intf_out);
			//hash_state = hash_state_cmd;

			//if(cmd_in == cmd_hash_done)		break;
			return hash_intf_out;
		}

		if(hash_mem_we)			hash_node_mem[hash_mem_wr_addr] = hash_mem_wr_data;		//write
		else hash_mem_rd_data = hash_node_mem[hash_mem_rd_addr];						//read
		
		if(hash_row_hdr_mem_we)	hash_row_hdr_mem[hash_row_hdr_mem_wr_addr] = hash_row_hdr_mem_wr_data;	//write
		else hash_row_hdr_mem_rd_data = hash_row_hdr_mem[hash_row_hdr_mem_rd_addr];						//read
		
		if(avail_mem_stack_we)	avail_mem_stack[avail_mem_stack_wr_addr] = avail_mem_stack_wr_data;		//write
		else avail_mem_stack_rd_data = avail_mem_stack[avail_mem_stack_rd_addr];						//read
	}
}

#define NUM_TEST_CASES 10
int main ()
{
	//initialize avail mem stack
	for(avail_mem_addr_t i=0; i<HASH_TBL_MEM_SIZE; i++) 
	{
		avail_mem_stack[i] = i;
	}	
	tos = HASH_TBL_MEM_SIZE-1;	//top of stack

	//initialize all row header addresses as invalid
	for(hash_row_hdr_addr_t i = 0; i<HASH_TBL_NUM_ROWS-1; i++) 
	{
		hash_row_hdr_mem[i] = HASH_TBL_MEM_INVALID_ADDR;
	}

	tcp_stream_hashkey_t hashkey[NUM_TEST_CASES];
	tcp_stream_hash_data_t hash_data[NUM_TEST_CASES];
	
	hash_intf_in_t hash_intf_in;
	hash_intf_out_t hash_intf_out;

	int tmp = 255;
	for(int cnt = 0; cnt < 2; cnt++)	{

		printf("\nPhase %d\n", cnt);	fflush(stdout);
		int i;
		
		for(i=0; i<NUM_TEST_CASES; i++){
			
			hashkey[i].ip_1 = ++tmp;
			hashkey[i].ip_2 = ++tmp;
			hashkey[i].tcp_port_1 = ++tmp;
			hashkey[i].tcp_port_2 = ++tmp;

			hash_data[i].stream_state = i;
			printf("\nTest case: %d, hash_value: %u", i, (hash_func(hashkey[i])&(HASH_TBL_NUM_ROWS-1)) );	fflush(stdout);
			tmp+=7;
		}

		printf("\nPrepared\n");

		for(i=0; i<NUM_TEST_CASES; i++){
			
			hash_intf_in.hashkey = hashkey[i];
			hash_intf_in.hash_data = hash_data[i];
			hash_intf_in.cmd = cmd_find;
			
			hash_intf_out = hash_module(hash_intf_in);

			if(hash_intf_out.hash_ret == error)	{
				hash_intf_in.cmd = cmd_insert;
			}
			else {
				printf("\nTest case: %d Error: Invalid entry found!!!", i);	fflush(stdout);
			}

			hash_intf_out = hash_module(hash_intf_in);
			if(hash_intf_out.hash_ret != inserted)	{
				printf("\nTest case: %d Insert Error!!!", i);	fflush(stdout);
			}
			else {
				printf("\nTest case: %d, hash_node_addr = %u, hash_data = %d", i, hash_intf_out.hash_node_addr, hash_intf_out.hash_data.stream_state);	fflush(stdout);
			}
		}

		printf("\nInserted\n");	fflush(stdout);
		
		for(i=0; i<NUM_TEST_CASES; i++){
			
			hash_intf_in.hashkey = hashkey[i];
			hash_intf_in.cmd = cmd_find;
			
			hash_intf_out = hash_module(hash_intf_in);

			if(hash_intf_out.hash_ret != found)	{
				printf("\nTest case: %d Find Error!!!", i);	fflush(stdout);
				continue;
			}
			else {
				printf("\nTest case: %d, hash_node_addr = %u, hash_data = %d", i, hash_intf_out.hash_node_addr, hash_intf_out.hash_data.stream_state);	fflush(stdout);			
			}

			hash_intf_in.hash_node_addr = hash_intf_out.hash_node_addr;
			hash_intf_in.cmd = cmd_delete;
			
			if(i%2)	{
				printf("\nTest case: %d Delete Request", i);	fflush(stdout);
				hash_intf_out = hash_module(hash_intf_in);
				if(hash_intf_out.hash_ret != deleted)	{
					printf("\nTest case: %d Delete Error!!!", i);	fflush(stdout);
				}
			}
		}

		printf("\nDeleted\n");	fflush(stdout);
		
		for(i=0; i<NUM_TEST_CASES; i++){
			
			hash_intf_in.hashkey = hashkey[i];
			hash_intf_in.cmd = cmd_find;
			
			hash_intf_out = hash_module(hash_intf_in);

			if(hash_intf_out.hash_ret != found)	{
				printf("\nTest case: %d Find Error!!!", i);	fflush(stdout);
			}
			else {
				printf("\nTest case: %d, hash_node_addr = %u, hash_data = %d", i, hash_intf_out.hash_node_addr, hash_intf_out.hash_data.stream_state);	fflush(stdout);
				continue;
			}
		}
		
		printf("\nSearched\n");	fflush(stdout);
		
		for(i=0; i<NUM_TEST_CASES; i++){
			
			hash_intf_in.hashkey = hashkey[i];
			hash_intf_in.hash_data = hash_data[i];
			hash_intf_in.cmd = cmd_find;
			
			hash_intf_out = hash_module(hash_intf_in);

			if(hash_intf_out.hash_ret == found)	continue;
			
			hash_intf_in.cmd = cmd_insert;
			hash_intf_out = hash_module(hash_intf_in);
			if(hash_intf_out.hash_ret != inserted)	{
				printf("\nTest case: %d Insert Error!!!", i);	fflush(stdout);
			}
			else {
				printf("\nTest case: %d, hash_node_addr = %u, hash_data = %d", i, hash_intf_out.hash_node_addr, hash_intf_out.hash_data.stream_state);	fflush(stdout);
			}
		}

		printf("\nInserted Again\n");	fflush(stdout);

		for(i=0; i<NUM_TEST_CASES; i++){
			
			hash_intf_in.hashkey = hashkey[i];
			hash_intf_in.hash_data = hash_data[i];
			hash_intf_in.cmd = cmd_find;
			
			hash_intf_out = hash_module(hash_intf_in);

			if(hash_intf_out.hash_ret != found)	{
				printf("\nTest case: %d Find Error!!!", i);	fflush(stdout);
				continue;
			}
			else {
				printf("\nTest case: %d, hash_node_addr = %u, hash_data = %d", i, hash_intf_out.hash_node_addr, hash_intf_out.hash_data.stream_state);	fflush(stdout);
			}

			hash_intf_in.hash_node_addr = hash_intf_out.hash_node_addr;
			hash_intf_in.cmd = cmd_delete;

			hash_intf_out = hash_module(hash_intf_in);
			if(hash_intf_out.hash_ret != deleted)	{
				printf("\nTest case: %d Delete Error!!!", i);	fflush(stdout);
			}

		}

		printf("\nDeleted All\n");	fflush(stdout);

		
		for(i=0; i<NUM_TEST_CASES; i++){
			
			hash_intf_in.hashkey = hashkey[i];
			hash_intf_in.cmd = cmd_find;
			
			hash_intf_out = hash_module(hash_intf_in);

			if(hash_intf_out.hash_ret != found)	{
				printf("\nTest case: %d Find Error!!!", i);	fflush(stdout);
			}
			else {
				printf("\nTest case: %d, hash_node_addr = %u, hash_data = %d", i, hash_intf_out.hash_node_addr, hash_intf_out.hash_data.stream_state);	fflush(stdout);
				continue;
			}
		}

		printf("\nSearched\n");	fflush(stdout);
	}
	
	printf("\n");	fflush(stdout);
	return 0;
}
#endif	//HASH_CL
