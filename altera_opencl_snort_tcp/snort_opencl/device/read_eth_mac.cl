#ifndef READ_ETH_MAC_CL
#define READ_ETH_MAC_CL

#ifndef	EMUL

__kernel void pre_parser(void)	
{

	pre_parser_state_t state = pre_parser_state_start;
	bool wr_pkt_data, end_of_pkt;

	data_stream_t data_stream;
	
	
	for (;;)	
	{
		rx_channel_data_t rx_packet = read_channel_altera(inputChannel_1);

		bool start_of_packet = rx_packet.header[0] & MASK_START_OF_PACKET;
		bool end_of_packet = rx_packet.header[0] & MASK_END_OF_PACKET;
		
		wr_pkt_data = 0;
		end_of_pkt = 0;
		
		if(state == pre_parser_state_start) 
		{			
			if(start_of_packet)	
			{
				wr_pkt_data = 1;
				state = pre_parser_state_cont;
			}
		}
		else if(state == pre_parser_state_cont) 
		{
			wr_pkt_data = 1;
			if(end_of_packet)	
			{
				state = pre_parser_state_start;
			}
		}
		
		if(wr_pkt_data)	
		{			
			for(uint8_t i=0; i<2; i++) 
			{
				if(i == 0)	
				{
					data_stream.data[0] = (rx_packet.data & 0xFF);
					data_stream.data[1] = ((rx_packet.data>>8) & 0xFF);
					data_stream.data[2] = ((rx_packet.data>>16) & 0xFF);
					data_stream.data[3] = ((rx_packet.data>>24) & 0xFF);
				}
				else 
				{
					data_stream.data[0] = ((rx_packet.data>>32) & 0xFF);
					data_stream.data[1] = ((rx_packet.data>>40) & 0xFF);
					data_stream.data[2] = ((rx_packet.data>>48) & 0xFF);
					data_stream.data[3] = ((rx_packet.data>>56) & 0xFF);
					end_of_pkt = end_of_packet;
				}
				write_channel_altera(ch_data_stream[ETH], data_stream);
				write_channel_altera(ch_end_of_pkt[ETH], end_of_pkt);
			}
		}
	}
}

#else

__kernel void pre_parser(QDR uint16_t* restrict pkt_len, QDR uint8_t* restrict pkt_data)		
{

	bool 		end_of_pkt;
	data_stream_t 	data_stream;
	uint16_t 		offset;

	offset = 0;
	do	
	{

		data_stream.data[0] = pkt_data[offset++];
		data_stream.data[1] = pkt_data[offset++];
		data_stream.data[2] = pkt_data[offset++];
		data_stream.data[3] = pkt_data[offset++];

		if(offset >= (*pkt_len))	end_of_pkt = 1;
		else end_of_pkt = 0;

		write_channel_altera(ch_data_stream[ETH], data_stream);
		write_channel_altera(ch_end_of_pkt[ETH], end_of_pkt);
		
	} while(!end_of_pkt);
}

#endif

#endif
