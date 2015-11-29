#ifndef TCP_REASSEMBLY_CL
#define TCP_REASSEMBLY_CL

__kernel void tcp_stream_reassembly(void)
{
	tcp_stream_hashkey_t	tcp_stream_hashkey;
	tcp_stream_hash_data_t	tcp_stream_hash_data;
	hash_node_addr_t 		hash_node_addr;
	hash_cmd_t 				hash_cmd;
	hash_ret_t 				hash_ret;
	
	bool 					dir; 
	uint8_t 				tcp_flags;
	stream_state_t  		stream_state, stream_state_prev;
	tcp_inspect_cmd_t 		tcp_inspect_cmd;
	tcp_reassembly_state_t 	tcp_reassembly_state;

	bool 					hash_module_update, tcp_inspect_data_flow_cntl;

	eth_hdr_struct			eth_hdr;
	ipv4_hdr_struct			ipv4_hdr;
	tcp_hdr_struct			tcp_hdr;

	uint8_t 				slot;			
	uint16_t 				tcp_seg_len;

	bool err;
	
	hash_intf_out_t hash_intf_out;
	hash_intf_in_t  hash_intf_in;

	uint16_t stream_state_update_mem_addr;
	uint8_t  stream_state_update_mem_data;

	bool ack_flag, rst_flag, syn_flag, fin_flag;
	
	tcp_reassembly_state = state_read_eth;

	uint16_t count = 0;
	
	while(1)	
	{			
		if(tcp_reassembly_state == state_read_eth)		
		{				
			eth_hdr  = read_channel_altera(ch_eth_hdr);
			count++;
		
			if(eth_hdr.eth_type == ETH_TYPE_IPV4)	tcp_reassembly_state = state_read_ipv4;

			tcp_inspect_data_flow_cntl = 0;
			hash_module_update = 0;
		}
		
		else if(tcp_reassembly_state == state_read_ipv4)	
		{			
			ipv4_hdr = read_channel_altera(ch_ipv4_hdr);
			
			if( ipv4_hdr.ip_p == IPV4_PROTO_TCP)	tcp_reassembly_state = state_read_tcp;
			else	tcp_reassembly_state = state_read_eth;

			tcp_inspect_data_flow_cntl = 0;
			hash_module_update = 0;
		}
		
		else if(tcp_reassembly_state == state_read_tcp) 	
		{			
			tcp_hdr  = read_channel_altera(ch_tcp_hdr);
			tcp_reassembly_state = state_read;

			tcp_inspect_data_flow_cntl = 0;
			hash_module_update = 0;
		}

		else if (tcp_reassembly_state == state_read)	
		{			
			tcp_flags = tcp_hdr.th_flags;
			tcp_seg_len = ipv4_hdr.ip_len - (ipv4_hdr.ip_hl<<2) - (tcp_hdr.th_off<<2);
			dir = (ipv4_hdr.ip_src > ipv4_hdr.ip_dst);
			
			if(dir == 0)	// 1 -> 2	
			{

				tcp_stream_hashkey.ip_1 	  = ipv4_hdr.ip_src;
				tcp_stream_hashkey.ip_2 	  = ipv4_hdr.ip_dst;
				tcp_stream_hashkey.tcp_port_1 = tcp_hdr.th_sport;
				tcp_stream_hashkey.tcp_port_2 = tcp_hdr.th_dport;
			}
			else	// 2 -> 1	
			{
				tcp_stream_hashkey.ip_1 	  = ipv4_hdr.ip_dst;
				tcp_stream_hashkey.ip_2 	  = ipv4_hdr.ip_src;
				tcp_stream_hashkey.tcp_port_1 = tcp_hdr.th_dport;
				tcp_stream_hashkey.tcp_port_2 = tcp_hdr.th_sport;
						
			}

			tcp_inspect_data_flow_cntl = 0;
			
			//find in hash table
			hash_module_update = 1;
			hash_cmd = cmd_find;
			
			tcp_reassembly_state = state_update;
			
		}	

		else if(tcp_reassembly_state == state_update)	
		{
			if(hash_ret == error)	stream_state = closed;								//not found, need to insert new
			else					stream_state = tcp_stream_hash_data.stream_state;	//entry exisis, retrieve stream_state
			
			stream_state_prev = stream_state;

//check flags and update state
#ifdef SS_UPDATE_MEM
			ack_flag = (tcp_flags & ACK_FLAG_MASK) == ACK_FLAG_MASK;
			rst_flag = (tcp_flags & RST_FLAG_MASK) == RST_FLAG_MASK;
			syn_flag = (tcp_flags & SYN_FLAG_MASK) == SYN_FLAG_MASK;
			fin_flag = (tcp_flags & FIN_FLAG_MASK) == FIN_FLAG_MASK;

			stream_state_update_mem_addr = (fin_flag | (syn_flag<<1) | (rst_flag<<2) | (ack_flag<<3) | (stream_state<<4) | (dir<<8))&0x1FF;
			stream_state_update_mem_data = stream_state_update_mem[stream_state_update_mem_addr];

			stream_state = (stream_state_update_mem_data>>4) & 0x0F;
			err = (stream_state_update_mem_data & 0x01);
#else
			stream_state_update_func(&stream_state, &tcp_flags, &dir, &err);
#endif				
			if(err) 
			{				
				//stream_state mismatch
				//report error

#ifdef EMUL
				//printf("\nStream State mismatch report error: %d!!!", count);
				printf("\nStream State mismatch report error!!!");
#endif
				tcp_inspect_data_flow_cntl 	 = 1;
				tcp_inspect_cmd 			 = cmd_pass_through;

				hash_module_update = 0;
				
				tcp_reassembly_state		 = state_read_eth;
				
			}
			
			//valid flags for this stream_state
			else if(hash_ret == error)	
			{				
				//not found, need to insert new 			

				tcp_stream_hash_data.stream_state = stream_state;
				tcp_stream_hash_data.slot_dir_valid = 0x00;	//all invalid
				
				tcp_inspect_data_flow_cntl 	= 1;
				tcp_inspect_cmd 			= cmd_pass_through;
				
				//call hash module to insert. For now, assume that ret is successful
				hash_module_update = 1;
				hash_cmd  = cmd_insert;

				tcp_reassembly_state = state_read_eth;				
			}
			
			//entry exisis
			else if(stream_state == closed) 	
			{
				//stream closed, delete entry
				tcp_stream_hash_data.stream_state = stream_state;
				
				tcp_inspect_data_flow_cntl 	= 1;
				tcp_inspect_cmd 			= cmd_pass_through;
				
				hash_module_update = 1;
				hash_cmd = cmd_delete;
				
				tcp_reassembly_state = state_read_eth;
			}
		
			else if( !((stream_state_prev == open) && (stream_state == open)) ) 	
			{
				//only handshaking, no payload involved
				tcp_stream_hash_data.stream_state = stream_state;

				//update expected seq numbers
				if(stream_state == syn_ack)	
				{
					if(dir==0)	tcp_stream_hash_data.seq_num_exp[0] = tcp_hdr.th_seq+1;
					else		tcp_stream_hash_data.seq_num_exp[1] = tcp_hdr.th_seq+1;
				}
				else if(stream_state == open)	
				{
					if(dir==0)	tcp_stream_hash_data.seq_num_exp[0] = tcp_hdr.th_seq;
					else		tcp_stream_hash_data.seq_num_exp[1] = tcp_hdr.th_seq;					
				}
					
				tcp_inspect_data_flow_cntl	= 1;	
				tcp_inspect_cmd 			= cmd_pass_through;

				hash_module_update = 1;
				hash_cmd = cmd_update;
				
				tcp_reassembly_state = state_read_eth;
			}
				
			//dir 1 -> 2
			else if(dir == 0)	
			{
				if(tcp_hdr.th_seq == tcp_stream_hash_data.seq_num_exp[0])	
				{		
					//update expected sequence number
					tcp_stream_hash_data.seq_num_exp[0] += tcp_seg_len;
		
					//stream data through
					tcp_inspect_data_flow_cntl	= 1;	
					tcp_inspect_cmd 			 = cmd_pass_through;

					hash_module_update = 0;
					
					tcp_reassembly_state		 = state_chk_slot_pkt_dir_0;										
				}
				
				//out of order packet
				else 
				{		
					//search for empty slot 
					
					slot = 0xFF;
					
					if((tcp_stream_hash_data.slot_dir_valid & 0x03)==0x00 ) 	//slot 0 empty
					{
						slot=0; tcp_stream_hash_data.slot_dir_valid |= 0x01;	//slot: 0, dir: 0, valid: 1
						tcp_stream_hash_data.seg_len_slot[0] = tcp_seg_len;
					}
					else if((tcp_stream_hash_data.slot_dir_valid & (0x03<<2))==0x00 )		//slot 1 empty
					{
						slot=1; tcp_stream_hash_data.slot_dir_valid |= (0x01<<2);			//slot: 1, dir: 0, valid: 1
						tcp_stream_hash_data.seg_len_slot[1] = tcp_seg_len;
					}
					else if((tcp_stream_hash_data.slot_dir_valid & (0x03<<4))==0x00 )		//slot 2 empty
					{
						slot=2; tcp_stream_hash_data.slot_dir_valid |= (0x01<<4);			//slot: 2, dir: 0, valid: 1
						tcp_stream_hash_data.seg_len_slot[2] = tcp_seg_len;
					}
					else if((tcp_stream_hash_data.slot_dir_valid & (0x03<<6))==0x00 )		//slot 3 empty
					{
						slot=3; tcp_stream_hash_data.slot_dir_valid |= (0x01<<6);			//slot: 3, dir: 0, valid: 1
						tcp_stream_hash_data.seg_len_slot[3] = tcp_seg_len;
					}
#ifdef EMUL					
					else	
					{
						printf("\nNo more slots for out of order packets");
					}
#endif					
					//write data to that slot		
					tcp_inspect_data_flow_cntl	= 1;
					tcp_inspect_cmd = cmd_write_packet;

					//update hash entry
					hash_module_update = 1;
					hash_cmd  = cmd_update;
					
					tcp_reassembly_state = state_read_eth;
				}
			}
				
			//dir 2 -> 1
			else if(dir == 1)	
			{
				if(tcp_hdr.th_seq == tcp_stream_hash_data.seq_num_exp[1])	
				{		
					//update expected sequence number
					tcp_stream_hash_data.seq_num_exp[1] += tcp_seg_len;
		
					//stream data through
					tcp_inspect_data_flow_cntl	= 1;
					tcp_inspect_cmd 			= cmd_pass_through;

					hash_module_update = 0;
					
					tcp_reassembly_state		 = state_chk_slot_pkt_dir_1;					
				}
		
				//out of order packet
				else 
				{		
					//search for empty slot 
					
					slot = 0xFF;
					
					if((tcp_stream_hash_data.slot_dir_valid & 0x03)==0x00 ) 	//slot 0 empty
					{
						slot=0; tcp_stream_hash_data.slot_dir_valid |= 0x03;	//slot: 0, dir: 1, valid: 1
						tcp_stream_hash_data.seg_len_slot[0] = tcp_seg_len;
					}
					else if((tcp_stream_hash_data.slot_dir_valid & (0x03<<2))==0x00 )		//slot 1 empty
					{
						slot=1; tcp_stream_hash_data.slot_dir_valid |= (0x03<<2);			//slot: 1, dir: 1, valid: 1
						tcp_stream_hash_data.seg_len_slot[1] = tcp_seg_len;
					}
					else if((tcp_stream_hash_data.slot_dir_valid & (0x03<<4))==0x00 )		//slot 2 empty
					{
						slot=2; tcp_stream_hash_data.slot_dir_valid |= (0x03<<4);			//slot: 2, dir: 1, valid: 1
						tcp_stream_hash_data.seg_len_slot[2] = tcp_seg_len;
					}
					else if((tcp_stream_hash_data.slot_dir_valid & (0x03<<6))==0x00 )		//slot 3 empty
					{
						slot=3; tcp_stream_hash_data.slot_dir_valid |= (0x03<<6);			//slot: 3, dir: 1, valid: 1
						tcp_stream_hash_data.seg_len_slot[3] = tcp_seg_len;
					}
#ifdef EMUL					
					else	
					{
						printf("\nNo more slots for out of order packets");
					}
#endif					
					//write data to that slot
					tcp_inspect_data_flow_cntl	= 1;
					tcp_inspect_cmd 			= cmd_write_packet;
		
					//update hash entry
					hash_module_update = 1;
					hash_cmd  = cmd_update;

					tcp_reassembly_state = state_read_eth;
				}
			}
		}
		
		else if(tcp_reassembly_state == state_chk_slot_pkt_dir_0)
		{
			//check if any of the packet slot is the next packet
		
			slot = 0xFF;
		
			if( ((tcp_stream_hash_data.slot_dir_valid & (0x03)) == 0x01) && 	//slot: 0, dir: 0, valid: 1
				(tcp_stream_hash_data.seq_num_exp[0] == tcp_stream_hash_data.seq_num_slot[0]) ) 							
			{
				slot = 0;	tcp_stream_hash_data.slot_dir_valid &= (~0x03); 	//invalidate slot 0
				tcp_seg_len = tcp_stream_hash_data.seg_len_slot[0];
			}
			else if( ((tcp_stream_hash_data.slot_dir_valid & (0x03<<2)) == (0x01<<2)) &&	//slot: 1, dir: 0, valid: 1
					 (tcp_stream_hash_data.seq_num_exp[0] == tcp_stream_hash_data.seq_num_slot[1]) )	
			{	
				slot = 1;	tcp_stream_hash_data.slot_dir_valid &= (~(0x03<<2));			//invalidate slot 1
				tcp_seg_len = tcp_stream_hash_data.seg_len_slot[1];
			}
			else if( ((tcp_stream_hash_data.slot_dir_valid & (0x03<<4)) == (0x01<<4)) &&	//slot: 2, dir: 0, valid: 1
					 (tcp_stream_hash_data.seq_num_exp[0] == tcp_stream_hash_data.seq_num_slot[2]) )	
			{	
				slot = 2;	tcp_stream_hash_data.slot_dir_valid &= (~(0x03<<4));			//invalidate slot 2
				tcp_seg_len = tcp_stream_hash_data.seg_len_slot[2];
			}
			else if( ((tcp_stream_hash_data.slot_dir_valid & (0x03<<6)) == (0x01<<6)) &&	//slot: 3, dir: 0, valid: 1
					 (tcp_stream_hash_data.seq_num_exp[0] == tcp_stream_hash_data.seq_num_slot[3]) )	
			{	
				slot = 3;	tcp_stream_hash_data.slot_dir_valid &= (~(0x03<<6));			//invalidate slot 3
				tcp_seg_len = tcp_stream_hash_data.seg_len_slot[3];
			} 
			
			if(slot != 0xFF)	
			{	
				//some valid slot found
				tcp_stream_hash_data.seq_num_exp[0] += tcp_seg_len;
		
				//stream data through
				tcp_inspect_data_flow_cntl	 = 1;
				tcp_inspect_cmd 			 = cmd_read_packet;

				hash_module_update = 0;
				
				tcp_reassembly_state		 = state_chk_slot_pkt_dir_0;
			}
			else 
			{
				tcp_inspect_data_flow_cntl	 = 0;

				hash_module_update = 1;
				hash_cmd = cmd_update;				

				tcp_reassembly_state = state_read_eth;
			}
		}
		
		else if(tcp_reassembly_state == state_chk_slot_pkt_dir_1)
		{
			//check if any of the packet slot is the next packet
		
			slot = 0xFF;
		
			if( ((tcp_stream_hash_data.slot_dir_valid & (0x03)) == 0x03) && 	//slot: 0, dir: 1, valid: 1
				(tcp_stream_hash_data.seq_num_exp[1] == tcp_stream_hash_data.seq_num_slot[0]) ) 
			{		
				slot = 0;	tcp_stream_hash_data.slot_dir_valid &= (~0x03); 	//invalidate slot 0
				tcp_seg_len = tcp_stream_hash_data.seg_len_slot[0];
			}
			else if( ((tcp_stream_hash_data.slot_dir_valid & (0x03<<2)) == (0x03<<2)) &&	//slot: 1, dir: 1, valid: 1
					 (tcp_stream_hash_data.seq_num_exp[1] == tcp_stream_hash_data.seq_num_slot[1]) )	
			{	
				slot = 1;	tcp_stream_hash_data.slot_dir_valid &= (~(0x03<<2));			//invalidate slot 1
				tcp_seg_len = tcp_stream_hash_data.seg_len_slot[1];
			}
			else if( ((tcp_stream_hash_data.slot_dir_valid & (0x03<<4)) == (0x03<<4)) &&	//slot: 2, dir: 1, valid: 1
					 (tcp_stream_hash_data.seq_num_exp[1] == tcp_stream_hash_data.seq_num_slot[2]) )	
			{	
				slot = 2;	tcp_stream_hash_data.slot_dir_valid &= (~(0x03<<4));			//invalidate slot 2
				tcp_seg_len = tcp_stream_hash_data.seg_len_slot[2];
			}
			else if( ((tcp_stream_hash_data.slot_dir_valid & (0x03<<6)) == (0x03<<6)) &&	//slot: 3, dir: 1, valid: 1
					 (tcp_stream_hash_data.seq_num_exp[1] == tcp_stream_hash_data.seq_num_slot[3]) )	
			{	
				slot = 3;	tcp_stream_hash_data.slot_dir_valid &= (~(0x03<<6));			//invalidate slot 3
				tcp_seg_len = tcp_stream_hash_data.seg_len_slot[3];
			} 
			
			if(slot != 0xFF)	
			{
				//some valid slot found
				tcp_stream_hash_data.seq_num_exp[1] += tcp_seg_len;
		
				//stream data through
				tcp_inspect_data_flow_cntl	 = 1;
				tcp_inspect_cmd 			 = cmd_read_packet;

				hash_module_update = 0;
				
				tcp_reassembly_state		 = state_chk_slot_pkt_dir_1;							
			}
			else 
			{
				tcp_inspect_data_flow_cntl	 = 0;

				hash_module_update = 1;
				hash_cmd = cmd_update;				

				tcp_reassembly_state = state_read_eth;
			}
		}
		
		if(tcp_inspect_data_flow_cntl)
		{
			tcp_inspect_data_flow_t tcp_inspect_data_flow;
			
			tcp_inspect_data_flow.tcp_inspect_cmd = tcp_inspect_cmd;
			tcp_inspect_data_flow.tcp_stream_addr = hash_node_addr;
			tcp_inspect_data_flow.slot = slot;
			tcp_inspect_data_flow.dir  = dir;

			tcp_segment_struct_t tcp_segment_struct;
			tcp_segment_struct.tcp_seg_len = tcp_seg_len;
			tcp_segment_struct.tcp_stream_hashkey = tcp_stream_hashkey;
			
			write_channel_altera(ch_tcp_inspect_data_flow, tcp_inspect_data_flow);

			if((tcp_inspect_cmd == cmd_pass_through) || (tcp_inspect_cmd == cmd_read_packet))
				write_channel_altera(ch_tcp_segment, tcp_segment_struct);
			
			tcp_inspect_data_flow_cntl = 0;	//reset variable
		}

		if(hash_module_update)	
		{
			hash_intf_in.cmd			= hash_cmd;
			hash_intf_in.hashkey		= tcp_stream_hashkey;
			hash_intf_in.hash_data		= tcp_stream_hash_data;
			hash_intf_in.hash_node_addr = hash_node_addr;
			
			write_channel_altera(ch_hash_intf_in, hash_intf_in);
			hash_intf_out = read_channel_altera(ch_hash_intf_out);
			
			hash_node_addr 	  	 = hash_intf_out.hash_node_addr;
			tcp_stream_hash_data = hash_intf_out.hash_data;
			hash_ret 			 = hash_intf_out.hash_ret;

			hash_module_update = 0;	//reset variable

#ifdef EMUL
			//if(hash_cmd == cmd_insert)	printf( "\nhash node addr = %u", hash_func(tcp_stream_hashkey)&(HASH_TBL_NUM_ROWS-1) );
#endif
		}
	}
}

#endif
