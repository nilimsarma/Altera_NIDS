#ifndef HASH_CL
#define HASH_CL

__kernel void hash_module(void)
{

	hash_node_struct	hash_node_mem	[HASH_TBL_MEM_SIZE];		// 48*1024 = 48 KB
	hash_node_addr_t	hash_row_hdr_mem[HASH_TBL_NUM_ROWS];		// 2*256 = 512
	avail_mem_addr_t	avail_mem_stack [HASH_TBL_MEM_SIZE];		// 2*1024 = 2 KB

	//initialize avail mem stack
	for(avail_mem_addr_t i=0; i<HASH_TBL_MEM_SIZE; i++) 
	{
		avail_mem_stack[i] = i;
	}	
	avail_mem_addr_t tos = HASH_TBL_MEM_SIZE-1;	//top of stack

	//initialize all row header addresses as invalid
	for(hash_row_hdr_addr_t i = 0; i<HASH_TBL_NUM_ROWS; i++) 
	{
		hash_row_hdr_mem[i] = HASH_TBL_MEM_INVALID_ADDR;
	}

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

	hash_intf_in_t  	hash_intf_in;
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
		
		if(hash_state == hash_state_cmd)	
		{
			hash_intf_in = read_channel_altera(ch_hash_intf_in);
#ifdef EMUL
			//print_hash_intf_in(hash_intf_in);
#endif		
			cmd_in 		  = hash_intf_in.cmd;
			hashkey_in 	  = hash_intf_in.hashkey; 
			hash_data_in 	  = hash_intf_in.hash_data;
			hash_node_addr_in = hash_intf_in.hash_node_addr;

			if(cmd_in == cmd_insert)		
			{
#ifdef EMUL
				if(tos == AVAIL_MEM_ADDR_EMPTY)	printf("\n Out of memory for hash table");
#endif				
				avail_mem_stack_rd_addr = tos;
				hash_state = hash_state_insert_0;
			}
			else if(cmd_in == cmd_delete)	
			{				
				hash_row_hdr_addr 	= hash_func(hashkey_in)&(HASH_TBL_NUM_ROWS-1);	
				hash_mem_rd_addr = hash_node_addr_in;								
				hash_state = hash_state_delete_0;
			}
			
			else if(cmd_in == cmd_find)		
			{
				hash_row_hdr_addr   = hash_func(hashkey_in)&(HASH_TBL_NUM_ROWS-1);
				hash_row_hdr_mem_rd_addr = hash_row_hdr_addr;
				hash_state = hash_state_find_0;
			}
			
			else if(cmd_in == cmd_update)	
			{				
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
			if(hash_node_addr_prev != HASH_TBL_MEM_INVALID_ADDR)	//valid
			{	
				hash_node.hash_addr_next = hash_node_addr;

				//update hash mem
				hash_mem_wr_addr = hash_node_addr_prev;
				hash_mem_wr_data = hash_node;
				hash_mem_we = 1;

			}
			else	//update the row hdr entry
			{	
				hash_row_hdr_mem_wr_addr = hash_func(hashkey_in)&(HASH_TBL_NUM_ROWS-1);
				hash_row_hdr_mem_wr_data = hash_node_addr;
				hash_row_hdr_mem_we = 1;
			}

			hash_node_curr.hashkey	= hashkey_in;
			hash_node_curr.hash_data = hash_data_in;
			hash_node_curr.hash_addr_prev = hash_node_addr_prev;
			hash_node_curr.hash_addr_next = HASH_TBL_MEM_INVALID_ADDR;

			hash_state = hash_state_insert_1;
			
		}
		else if (hash_state == hash_state_insert_1)
		{
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
			
			if(update_row_hdr)	
			{				
				hash_row_hdr_mem_wr_addr = hash_row_hdr_addr;
				hash_row_hdr_mem_wr_data = hash_row_hdr;
				hash_row_hdr_mem_we = 1;
			}
		
			if(update_node_prev)		hash_state = hash_state_delete_1;	
			else if(update_node_next)	hash_state = hash_state_delete_3;
			else hash_state = hash_state_delete_5;
			
		}

		else if (hash_state == hash_state_delete_1)
		{
			hash_mem_rd_addr = hash_node_addr_prev;
			hash_state = hash_state_delete_2;
		}
		
		else if (hash_state == hash_state_delete_2)	//update_node_prev
		{			
			hash_mem_rd_data.hash_addr_next = hash_node_addr_next;
			
			hash_mem_wr_addr = hash_node_addr_prev;
			hash_mem_wr_data = hash_mem_rd_data;
			hash_mem_we = 1;
		
			if(update_node_next)	hash_state = hash_state_delete_3;
			else hash_state = hash_state_delete_5;
		}

		else if (hash_state == hash_state_delete_3)	//update_node_next
		{			
			hash_mem_rd_addr_2 = hash_node_addr_next;
			hash_state = hash_state_delete_4;
		}
		
		else if (hash_state == hash_state_delete_4)
		{
			hash_mem_rd_data.hash_addr_prev = hash_node_addr_prev;
			hash_mem_wr_addr = hash_node_addr_next;
			hash_mem_wr_data = hash_mem_rd_data;
			hash_mem_we = 1;
			
			hash_state = hash_state_delete_5;
		}

		else if (hash_state == hash_state_delete_5)
		{
			tos++;
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
			else 
			{				
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
			if(hashkey_match == 0)	
			{
				hash_node_addr_prev = hash_node_addr_curr;
				hash_node_addr_curr = hash_node.hash_addr_next;
			}
			if( (hash_node_addr_curr == HASH_TBL_MEM_INVALID_ADDR) || (hashkey_match == 1) )
			{
				hash_state = hash_state_find_3;		
			}
			else 
			{
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
			else 
			{
				hash_ret_out  = error;
			}
			hash_state = hash_state_write_output;
		}

		else if (hash_state == hash_state_update_0) //input: hash_mem_addr_in, hash_data
		{
			hash_node = hash_mem_rd_data;
			hash_node.hash_data = hash_data_in;
			
			hash_mem_wr_addr = hash_node_addr_in;
			hash_mem_wr_data = hash_node;
			hash_mem_we = 1;

			hash_ret_out = success;
			hash_state = hash_state_write_output;
		}
		
		else if (hash_state == hash_state_write_output) 
		{
			hash_intf_out.hash_node_addr = hash_node_addr_out;
			hash_intf_out.hash_data		 = hash_data_out;
			hash_intf_out.hash_ret		 = hash_ret_out;
			
			write_channel_altera(ch_hash_intf_out, hash_intf_out);
			hash_state = hash_state_cmd;
#ifdef EMUL
			//print_hash_intf_out(hash_intf_out);
#endif
		}

		if(hash_mem_we)	hash_node_mem[hash_mem_wr_addr] = hash_mem_wr_data;
		else hash_mem_rd_data = hash_node_mem[hash_mem_rd_addr];		
		
		if(hash_row_hdr_mem_we)	hash_row_hdr_mem[hash_row_hdr_mem_wr_addr] = hash_row_hdr_mem_wr_data;
		else hash_row_hdr_mem_rd_data = hash_row_hdr_mem[hash_row_hdr_mem_rd_addr];						
		
		if(avail_mem_stack_we)	avail_mem_stack[avail_mem_stack_wr_addr] = avail_mem_stack_wr_data;		
		else avail_mem_stack_rd_data = avail_mem_stack[avail_mem_stack_rd_addr];						

#if 0 //def EMUL
		if(hash_mem_we)				printf("\nhash_mem_wr_addr = %u", hash_mem_wr_addr);
		if(hash_row_hdr_mem_we)		printf("\nhash_row_hdr_mem_wr_addr = %u, hash_row_hdr_mem_wr_data = %u", hash_row_hdr_mem_wr_addr, hash_row_hdr_mem_wr_data);
		if(avail_mem_stack_we)		printf("\nhash_mem_wr_addr = %u", avail_mem_stack_wr_addr);
#endif
	}
}

#endif	//HASH_CL
