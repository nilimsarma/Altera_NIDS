#ifndef TCP_REASSEMBLY_UTILS_H
#define TCP_REASSEMBLY_UTILS_H

#ifndef SS_UPDATE_MEM
void stream_state_update_func(stream_state_t* stream_state, uint8_t* tcp_flags, bool* dir, bool* err)
{
	*err = 1;
	
	if(*stream_state == closed) 
	{
		if( (*tcp_flags & (SYN_FLAG_MASK | ACK_FLAG_MASK | RST_FLAG_MASK | FIN_FLAG_MASK)) == SYN_FLAG_MASK )	//only syn flag	
		{
			*stream_state = syn; 
			*err = 0;
		}
	}
	else if(*stream_state == syn) 
	{
		if( (*tcp_flags & (SYN_FLAG_MASK | ACK_FLAG_MASK | RST_FLAG_MASK | FIN_FLAG_MASK)) == (SYN_FLAG_MASK | ACK_FLAG_MASK) )	//syn and ack
		{
			*stream_state = syn_ack; 
			*err = 0;
		}
	}
	else if(*stream_state == syn_ack) 
	{
		if( (*tcp_flags & (SYN_FLAG_MASK | ACK_FLAG_MASK | RST_FLAG_MASK | FIN_FLAG_MASK)) == ACK_FLAG_MASK )	//only ack
		{
			*stream_state = open; 
			*err = 0;
		}
	}
	else if(*stream_state == open) 
	{
		if( (*tcp_flags & (SYN_FLAG_MASK | RST_FLAG_MASK | FIN_FLAG_MASK)) == FIN_FLAG_MASK )	//only fin, no syn, rst
		{
			if(*dir == 0)	*stream_state = fin_1_ack_0_dir_0;
			else 			*stream_state = fin_1_ack_0_dir_1;

			*err = 0;
		}
		else if( (*tcp_flags & (SYN_FLAG_MASK | RST_FLAG_MASK | FIN_FLAG_MASK)) == 0x00 )	//no syn, rst, fin
		{
			*err = 0;
		}
	}
	else if(*stream_state == fin_1_ack_0_dir_0)	
	{
		if( ( (*tcp_flags & (SYN_FLAG_MASK | ACK_FLAG_MASK | RST_FLAG_MASK | FIN_FLAG_MASK)) == ACK_FLAG_MASK ) && (*dir == 1) )	//ack for fin 1	
		{
			*stream_state = fin_1_ack_1_dir_0; 
			*err = 0;
		}
	}
	else if(*stream_state == fin_1_ack_1_dir_0)	
	{
		if( ( (*tcp_flags & (SYN_FLAG_MASK | ACK_FLAG_MASK | RST_FLAG_MASK | FIN_FLAG_MASK)) == FIN_FLAG_MASK ) && (*dir == 0) )	//fin 2
		{
			*stream_state = fin_2_ack_1_dir_0; 
			*err = 0;
		}
	}
	else if(*stream_state == fin_2_ack_1_dir_0)	
	{
		if( ( (*tcp_flags & (SYN_FLAG_MASK | ACK_FLAG_MASK | RST_FLAG_MASK | FIN_FLAG_MASK)) == ACK_FLAG_MASK ) && (*dir == 1) )	//ack for fin 2
		{
			*stream_state = closed; 
			*err = 0;
		}
	}
	else if(*stream_state == fin_1_ack_0_dir_1)	
	{
		if( ( (*tcp_flags & (SYN_FLAG_MASK | ACK_FLAG_MASK | RST_FLAG_MASK | FIN_FLAG_MASK)) == ACK_FLAG_MASK ) && (*dir == 0) )	//ack for fin 1
		{
			*stream_state = fin_1_ack_1_dir_1; 
			*err = 0;
		}
	}
	else if(*stream_state == fin_1_ack_1_dir_1)	
	{
		if( ( (*tcp_flags & (SYN_FLAG_MASK | ACK_FLAG_MASK | RST_FLAG_MASK | FIN_FLAG_MASK)) == FIN_FLAG_MASK ) && (*dir == 1) )	//ack for fin 2
		{	
			*stream_state = fin_2_ack_1_dir_1; 
			*err = 0;
		}
	}
	else if(*stream_state == fin_2_ack_1_dir_1)	
	{
		if( ( (*tcp_flags & (SYN_FLAG_MASK | ACK_FLAG_MASK | RST_FLAG_MASK | FIN_FLAG_MASK)) == ACK_FLAG_MASK ) && (*dir == 0) )	//ack for fin 2
		{
			*stream_state = closed; 
			*err = 0;
		}
	}
}
#endif

#if 0
void hash_module_ch_write(hash_cmd_t* cmd, tcp_stream_hashkey_t* tcp_stream_hashkey, tcp_stream_hash_data_t* tcp_stream_hash_data,
	hash_node_addr_t* hash_node_addr)
{
	hash_intf_in_t hash_intf_in;

	hash_intf_in.cmd 			= *cmd;
	hash_intf_in.hashkey 		= *tcp_stream_hashkey;
	hash_intf_in.hash_data 		= *tcp_stream_hash_data;
	hash_intf_in.hash_node_addr = *hash_node_addr;

	write_channel_altera(ch_hash_intf_in, hash_intf_in);
}

bool hash_module_ch_read(tcp_stream_hash_data_t* tcp_stream_hash_data, hash_node_addr_t* hash_node_addr, hash_ret_t* ret)	
{
	bool valid;	
	hash_intf_out_t hash_intf_out;	

	hash_intf_out = read_channel_nb_altera(ch_hash_intf_out, &valid);

	*hash_node_addr 	  = hash_intf_out.hash_node_addr;
	*tcp_stream_hash_data = hash_intf_out.hash_data;
	*ret 				  = hash_intf_out.hash_ret;

	return valid;
}
#endif

uint32_t hash_func (tcp_stream_hashkey_t tcp_stream_hashkey)
{
	return (tcp_stream_hashkey.ip_1 ^ tcp_stream_hashkey.ip_2 ^	tcp_stream_hashkey.tcp_port_1 ^ tcp_stream_hashkey.tcp_port_2);
}

bool hashkey_comp_func (tcp_stream_hashkey_t tcp_stream_hashkey1, tcp_stream_hashkey_t tcp_stream_hashkey2)
{
	return ((tcp_stream_hashkey1.ip_1 == tcp_stream_hashkey2.ip_1) & 
			(tcp_stream_hashkey1.ip_2 == tcp_stream_hashkey2.ip_2) & 
			(tcp_stream_hashkey1.tcp_port_1 == tcp_stream_hashkey2.tcp_port_1) & 
			(tcp_stream_hashkey1.tcp_port_2 == tcp_stream_hashkey2.tcp_port_2));
}

#endif
