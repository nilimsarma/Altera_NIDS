#ifndef UTILS_CL
#define UTILS_CL

#ifdef EMUL
void print_ip_addr(uint32_t ip)
{
	printf("%u.%u.%u.%u\n",(ip>>24)&0xFF, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF);
}

void print_tcp_port(uint16_t tcp_port)
{
	printf("%u\n", tcp_port);
}

void print_tcp_hashkey(tcp_stream_hashkey_t hashkey)
{
	printf("\n");
	printf("IP 1: "); print_ip_addr(hashkey.ip_1);
	printf("IP 2: "); print_ip_addr(hashkey.ip_2);
	printf("TCP Port 1: "); print_tcp_port(hashkey.tcp_port_1);
	printf("TCP Port 2: "); print_tcp_port(hashkey.tcp_port_2);
}

void print_hash_intf_in(hash_intf_in_t hash_intf_in)
{
	printf("\nHash Intf In\n*********\n");
	printf("cmd = %s\n", hash_cmd_names[hash_intf_in.cmd]);	
	printf("Hashkey = \n");	print_tcp_hashkey(hash_intf_in.hashkey);
	printf("Hash node addr = %u\n", hash_intf_in.hash_node_addr);
}

void print_hash_intf_out(hash_intf_out_t hash_intf_out)
{
	printf("\nHash Intf Out\n*********\n");
	printf("ret = %s\n", hash_ret_names[hash_intf_out.hash_ret]);	
	printf("Hash node addr = %u\n", hash_intf_out.hash_node_addr);
}

void print_tcp_inspect_data_flow_struct(tcp_inspect_data_flow_t tcp_inspect_data_flow)
{
	printf("\ntcp_inspect_cmd: %s", tcp_inspect_cmd_names[tcp_inspect_data_flow.tcp_inspect_cmd]);
	printf("\ndir: %d", tcp_inspect_data_flow.dir);
	printf("\n");
}

void print_tcp_segment_struct(tcp_segment_struct_t tcp_segment_struct)
{
	print_tcp_hashkey(tcp_segment_struct.tcp_stream_hashkey);
	printf("\ntcp segment len: %d", tcp_segment_struct.tcp_seg_len);
	printf("\n");
}
#endif

#endif
