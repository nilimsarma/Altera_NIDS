#ifndef PARSER_CL
#define PARSER_CL

__kernel void eth_parser(void)
{	

	data_stream_t 		data_stream;	
	eth_hdr_struct 		eth_hdr;
	uint8_t				eth_hdr_arr[ETH_HDR_LEN];	
	parse_state 		state = HEADER_START;	
	data_stream_ch_t 	protocol = NUM_PROTOCOLS;	
	bool 				parse_next_protocol = 0;
	uint8_t 			eth_header_offset = 0;
	uint16_t 			eth_type = 0;

	bool				end_of_pkt = 0;	
	
	for(;;) 
	{	
		data_stream = read_channel_altera(ch_data_stream[ETH]);
		end_of_pkt = read_channel_altera(ch_end_of_pkt[ETH]);
		
		if(state == HEADER_START)
		{				
			protocol = NUM_PROTOCOLS;
			parse_next_protocol = 0;
			
			#pragma unroll
			for(uint8_t i=0; i<PARSER_WIN_SIZE; i++)	eth_hdr_arr[i] = data_stream.data[i];

			state = HEADER_CONT;
			eth_header_offset = PARSER_WIN_SIZE;
		}
		else if(state == HEADER_CONT)
		{
			#pragma unroll
			for(uint8_t i=0; i<PARSER_WIN_SIZE; i++)
			{
				eth_hdr_arr[eth_header_offset+i] = data_stream.data[i];
			}
			eth_header_offset+=PARSER_WIN_SIZE;

			if(eth_header_offset > ETH_HDR_LEN-PARSER_WIN_SIZE)	state = HEADER_END_PAYLOAD;
		}
		
		else if(state == HEADER_END_PAYLOAD)
		{
			
			#pragma unroll
			for(uint8_t i=0; i<ETH_HDR_LEN_OFFSET_WIN; i++)		eth_hdr_arr[eth_header_offset+i] = data_stream.data[i];

			eth_type = (data_stream.data[0]<<8)|(data_stream.data[1]);
			if(eth_type == ETH_TYPE_IPV4)
			{
				protocol = IPV4;
				parse_next_protocol = 1;
				state = PAYLOAD;
			}	
			else
			{
				state = UNKNOWN;
			}
			parse_eth_header(&eth_hdr_arr[0], &eth_hdr);	
			write_channel_altera(ch_eth_hdr, eth_hdr);
		}
		
		if(parse_next_protocol)		//pass data to the next protocol
		{
			if(protocol == IPV4) 
			{
				write_channel_altera(ch_data_stream[IPV4], data_stream);
				write_channel_altera(ch_end_of_pkt[IPV4], end_of_pkt);
			}
		}

		if(end_of_pkt)		state = HEADER_START;
	}
}

__kernel void ipv4_parser(void)
{	
	data_stream_t 		data_stream;
	ipv4_hdr_struct 	ipv4_hdr;
	uint8_t 			ipv4_hdr_arr[IPV4_HDR_LEN];
	parse_state 		state = HEADER_START;
	uint8_t 			ipv4_hdr_offset = 0;
	uint8_t 			ipv4_hdr_with_opt_len = 0;
	uint8_t 			ip_p;
	data_stream_ch_t 	protocol = NUM_PROTOCOLS;
	bool 				parse_next_protocol = 0;
	bool 				parse_hdr_done = 0;
	bool	 			end_of_pkt = 0;
	
	for(;;) 
	{		
		data_stream = read_channel_altera(ch_data_stream[IPV4]);
		end_of_pkt = read_channel_altera(ch_end_of_pkt[IPV4]);
		
		if(state == HEADER_START)
		{
			
			#pragma unroll
			for(uint8_t i=ETH_HDR_LEN_OFFSET_WIN; i<PARSER_WIN_SIZE; i++)	ipv4_hdr_arr[i-ETH_HDR_LEN_OFFSET_WIN] = data_stream.data[i];
			ipv4_hdr_with_opt_len = (ipv4_hdr_arr[IPV4_V_HL_OFFSET] & 0x0F)<<2;		//bits 3-0
			
			ipv4_hdr_offset = PARSER_WIN_SIZE-ETH_HDR_LEN_OFFSET_WIN;
			state = HEADER_CONT;			
			protocol = NUM_PROTOCOLS;			
			parse_next_protocol = 0;
			parse_hdr_done = 0;
		}
		
		else if(state == HEADER_CONT)
		{
			#pragma unroll
			for(uint8_t i=0; i<PARSER_WIN_SIZE; i++)	ipv4_hdr_arr[ipv4_hdr_offset+i] = data_stream.data[i];

			ipv4_hdr_offset+=PARSER_WIN_SIZE;
			if( ipv4_hdr_offset > (IPV4_HDR_LEN-PARSER_WIN_SIZE) )	
			{
				if(ipv4_hdr_with_opt_len == IPV4_HDR_LEN)
					state = HEADER_END_PAYLOAD;
				else
					state = HEADER_END_OPTIONS;
			}
		}
		else if(state == HEADER_END_PAYLOAD)
		{			
			#pragma unroll
			for(uint8_t i=0; i<IPV4_HDR_LEN_OFFSET_WIN; i++)	ipv4_hdr_arr[ipv4_hdr_offset+i] = data_stream.data[i];

			if(ipv4_hdr_arr[IPV4_PROTO_OFFSET] == IPV4_PROTO_TCP)
			{
				protocol = TCP;
				state = PAYLOAD;
				parse_next_protocol = 1;
			}
			else if(ipv4_hdr_arr[IPV4_PROTO_OFFSET] == IPV4_PROTO_UDP)
			{
				protocol = UDP;
				state = PAYLOAD;
				parse_next_protocol = 1;
			}
			else
			{
				state = UNKNOWN;
			}
			parse_hdr_done = 1;
			
		}		
		else if(state == HEADER_END_OPTIONS)
		{	
			#pragma unroll
			for(uint8_t i=0; i<IPV4_HDR_LEN_OFFSET_WIN; i++)	ipv4_hdr_arr[ipv4_hdr_offset+i] = data_stream.data[i];

			parse_hdr_done = 1;
			
			ipv4_hdr_offset+=PARSER_WIN_SIZE;
			if( ipv4_hdr_offset > (ipv4_hdr_with_opt_len-PARSER_WIN_SIZE) )
				state = HEADER_OPTIONS_END_PAYLOAD;
			else
				state = HEADER_OPTIONS_CONT;
		}
		
		else if(state == HEADER_OPTIONS_CONT)
		{
			ipv4_hdr_offset+=PARSER_WIN_SIZE;
			if( ipv4_hdr_offset > (ipv4_hdr_with_opt_len-PARSER_WIN_SIZE) )
				state = HEADER_OPTIONS_END_PAYLOAD;
			else
				state = HEADER_OPTIONS_CONT;
		}
		
		else if(state == HEADER_OPTIONS_END_PAYLOAD)
		{
			if(ipv4_hdr.ip_p== IPV4_PROTO_TCP)
			{
				protocol = TCP;
				state = PAYLOAD;
				parse_next_protocol = 1;
			}
			else if(ipv4_hdr.ip_p == IPV4_PROTO_UDP)
			{
				protocol = UDP;
				state = PAYLOAD;
				parse_next_protocol = 1;
			}
			else
			{
				state = UNKNOWN;
			}
		}
		
		if(parse_next_protocol)
		{
			if(protocol == TCP) 
			{
				write_channel_altera(ch_data_stream[TCP], data_stream);
				write_channel_altera(ch_end_of_pkt[TCP], end_of_pkt);
			}
		}
		if(parse_hdr_done)
		{
			parse_ipv4_header(&ipv4_hdr_arr[0], &ipv4_hdr);		
			write_channel_altera(ch_ipv4_hdr, ipv4_hdr);
			parse_hdr_done = 0;
		}
		
		if(end_of_pkt)		state = HEADER_START;
	}				
}

__kernel void tcp_parser(void)
{	

	data_stream_t 		data_stream;
	tcp_hdr_struct 		tcp_hdr;
	uint8_t 			tcp_hdr_arr[TCP_HDR_LEN];	
	parse_state 		state = HEADER_START;
	uint8_t 			tcp_hdr_offset = 0;
	uint8_t 			tcp_hdr_with_opt_len = 0;
	bool 				parse_next_protocol = 0;
	bool 				parse_hdr_done = 0;
	bool				end_of_pkt = 0;
	
	data_stream_ch_t 	protocol = NUM_PROTOCOLS;
	
	for(;;) 
	{	
		data_stream = read_channel_altera(ch_data_stream[TCP]);
		end_of_pkt = read_channel_altera(ch_end_of_pkt[TCP]);
		
		if(state == HEADER_START)
		{
			
			#pragma unroll
			for(uint8_t i=IPV4_HDR_LEN_OFFSET_WIN; i<PARSER_WIN_SIZE; i++)	tcp_hdr_arr[i-IPV4_HDR_LEN_OFFSET_WIN] = data_stream.data[i];

			state = HEADER_CONT;			
			tcp_hdr_offset = PARSER_WIN_SIZE-IPV4_HDR_LEN_OFFSET_WIN;
			tcp_hdr_with_opt_len = 0;			
			parse_next_protocol = 0;
			parse_hdr_done = 0;			
			protocol = NUM_PROTOCOLS;
		}
		
		else if(state == HEADER_CONT)
		{			
			#pragma unroll
			for(uint8_t i=0; i<PARSER_WIN_SIZE; i++)	tcp_hdr_arr[tcp_hdr_offset+i] = data_stream.data[i];
			
			tcp_hdr_offset+=PARSER_WIN_SIZE;
			
			if( tcp_hdr_offset > (TCP_HDR_LEN-PARSER_WIN_SIZE) ) 	
			{
				tcp_hdr_with_opt_len = (tcp_hdr_arr[TCP_OFF_OFFSET] & 0xF0)>>2;
				if(tcp_hdr_with_opt_len == TCP_HDR_LEN)
					state = HEADER_END_PAYLOAD;
				else
					state = HEADER_END_OPTIONS;
			}
		}
		
		else if(state == HEADER_END_PAYLOAD)
		{			
			#pragma unroll			
			for(uint8_t i=0; i<TCP_HDR_LEN_OFFSET_WIN; i++)	tcp_hdr_arr[tcp_hdr_offset+i] = data_stream.data[i];

			if( (tcp_hdr.th_sport == TCP_PORT_HTTP) || (tcp_hdr.th_dport == TCP_PORT_HTTP) )
			{
				protocol = HTTP;
				parse_next_protocol = 1 ;
				state = PAYLOAD;
			}
			else
				state = UNKNOWN;

			parse_hdr_done = 1;
		}
		else if(state == HEADER_END_OPTIONS)
		{	
			#pragma unroll
			for(uint8_t i=0; i<TCP_HDR_LEN_OFFSET_WIN; i++)	tcp_hdr_arr[tcp_hdr_offset+i] = data_stream.data[i];

			parse_hdr_done = 1;
			
			tcp_hdr_offset+=PARSER_WIN_SIZE;
			
			if( tcp_hdr_offset > (tcp_hdr_with_opt_len-PARSER_WIN_SIZE) )
				state = HEADER_OPTIONS_END_PAYLOAD;
			else
				state = HEADER_OPTIONS_CONT;
		}
				
		else if(state == HEADER_OPTIONS_CONT)
		{
			tcp_hdr_offset+=PARSER_WIN_SIZE;

			if( tcp_hdr_offset > (tcp_hdr_with_opt_len-PARSER_WIN_SIZE) )
				state = HEADER_OPTIONS_END_PAYLOAD;
			else
				state = HEADER_OPTIONS_CONT;
		}
		
		else if(state == HEADER_OPTIONS_END_PAYLOAD)
		{
		
			if( (tcp_hdr.th_sport == TCP_PORT_HTTP) || (tcp_hdr.th_dport == TCP_PORT_HTTP) )
			{
				protocol = HTTP;
				parse_next_protocol = 1 ;
				state = PAYLOAD;
			}
			else
				state = UNKNOWN;
		}

		if(parse_next_protocol)
		{
			write_channel_altera(ch_data_stream[TCP_INSPECT], data_stream);
			write_channel_altera(ch_end_of_pkt[TCP_INSPECT], end_of_pkt);
		}
		
		if(parse_hdr_done)
		{
			parse_tcp_header(&tcp_hdr_arr[0], &tcp_hdr);
			write_channel_altera(ch_tcp_hdr, tcp_hdr);
			parse_hdr_done = 0;
		}
		
		if(end_of_pkt)		state = HEADER_START;
	}				
}

__kernel void tcp_inspect(QDR stream_tcp_seg_size_t* restrict stream_tcp_seg_size, QDR stream_tcp_seg_data_t* restrict stream_tcp_seg_data)
{	
	tcp_inspect_state_t 	state;
	tcp_inspect_data_flow_t tcp_inspect_data_flow;
	
	data_stream_t 			data_stream;
	bool	  				end_of_pkt;

	bool  					write_data;
	uint16_t				curr_size;
	
	uint8_t 				slot;			
	bool					dir;
	uint16_t 				tcp_seg_len;
	hash_node_addr_t		tcp_stream_addr;
	tcp_inspect_cmd_t		tcp_inspect_cmd;
	tcp_stream_hashkey_t	tcp_stream_hashkey;
	
	uint32_t 				data;
	uint16_t				size;
	
	for(;;)
	{
			
		tcp_inspect_data_flow = read_channel_altera(ch_tcp_inspect_data_flow);

#ifdef EMUL
		//print_tcp_inspect_data_flow_struct(tcp_inspect_data_flow);
#endif

		tcp_inspect_cmd 	= tcp_inspect_data_flow.tcp_inspect_cmd;
		tcp_stream_addr 	= tcp_inspect_data_flow.tcp_stream_addr;
		slot 				= tcp_inspect_data_flow.slot;
		dir					= tcp_inspect_data_flow.dir;
		
		curr_size = 0;
		
		if(tcp_inspect_cmd == cmd_pass_through)	
		{
			state = state_pass_thru;
		}
		
		else if(tcp_inspect_cmd == cmd_read_packet)	
		{
			//size = stream_data[tcp_stream_addr].tcp_seg_size[slot];
			size = stream_tcp_seg_size[tcp_stream_addr].size[slot];
			state = state_read_pkt;
		}
		
		else if(tcp_inspect_cmd == cmd_write_packet) 
		{
			state = state_write_pkt;
		}

		for(;;)	
		{				
			if( (state == state_write_pkt) || (state == state_pass_thru) )	
			{					
				data_stream = read_channel_altera(ch_data_stream[TCP_INSPECT]);
				end_of_pkt  = read_channel_altera(ch_end_of_pkt[TCP_INSPECT]);

			
				if(state == state_write_pkt)	
				{					
					data = (data_stream.data[3]<<24) | (data_stream.data[2]<<16) | (data_stream.data[1]<<8) | data_stream.data[0];
					//stream_data[tcp_stream_addr].data[slot][curr_size] = data;
					stream_tcp_seg_data[tcp_stream_addr].data[slot][curr_size] = data;
					curr_size++;
					
					if(end_of_pkt)	//stream_data[tcp_stream_addr].tcp_seg_size[slot] = curr_size;
						stream_tcp_seg_size[tcp_stream_addr].size[slot] = curr_size;
				}
			}
			
			else if(state == state_read_pkt) 	
			{
				//data = stream_data[tcp_stream_addr].data[slot][curr_size];
				data = stream_tcp_seg_data[tcp_stream_addr].data[slot][curr_size];
				
				data_stream.data[0] = ( (data) & 0x0F);
				data_stream.data[1] = ( (data>>8) & 0x0F);
				data_stream.data[2] = ( (data>>16) & 0x0F);
				data_stream.data[3] = ( (data>>24) & 0x0F);
				
				curr_size++;
				
				if(curr_size == size)	end_of_pkt = 1;
				else end_of_pkt = 0;
			}
			
			if( (state == state_read_pkt) || (state == state_pass_thru) )	
			{				
				write_channel_altera(ch_data_stream[TCP_SEGMENT], data_stream);
				write_channel_altera(ch_end_of_pkt[TCP_SEGMENT], end_of_pkt);
			}

			if(end_of_pkt)	break;
		}
	}	
}

#define MATCH_CHAR 0xFF

__kernel void tcp_segment(uint32_t match_count_max)
{
	data_stream_t data_stream;
	bool	 	  end_of_pkt;
	parse_state   state = HEADER_START;
	uint16_t 	  curr_size, tcp_seg_len;
	tcp_segment_struct_t tcp_segment_struct;

	bool match;
	uint32_t match_count;
	
	match_count = 0;
	
	while(match_count < match_count_max)
	{
		tcp_segment_struct = read_channel_altera(ch_tcp_segment);
		tcp_seg_len = tcp_segment_struct.tcp_seg_len;

#ifdef EMUL		
		if(tcp_seg_len > 0)	print_tcp_segment_struct(tcp_segment_struct);
#endif

		state = HEADER_START;	
		curr_size = 0;
		match = 0;
		
		for(;;)	
		{			
			data_stream = read_channel_altera(ch_data_stream[TCP_SEGMENT]);
			end_of_pkt 	= read_channel_altera(ch_end_of_pkt[TCP_SEGMENT]);

			if(state == HEADER_START)
			{
				#pragma unroll
				for(uint8_t i=IPV4_HDR_LEN_OFFSET_WIN; i<PARSER_WIN_SIZE; i++)	
				{
					if(data_stream.data[i] == MATCH_CHAR)	match = 1;
				}
				
				curr_size = PARSER_WIN_SIZE - IPV4_HDR_LEN_OFFSET_WIN;
				
				if(curr_size < tcp_seg_len) state = HEADER_CONT;
				else state = UNKNOWN;
			}

			else if(state == HEADER_CONT)
			{
				#pragma unroll
				for(uint8_t i=0; i<PARSER_WIN_SIZE; i++)	
				{
					if(data_stream.data[i] == MATCH_CHAR)	match = 1;
				}

				curr_size += PARSER_WIN_SIZE;				
				if(curr_size >= tcp_seg_len) state = UNKNOWN;
			}

			
			if(end_of_pkt) 
			{
				match_count += match;
				break;				
			}
		}
	}
}

#endif
