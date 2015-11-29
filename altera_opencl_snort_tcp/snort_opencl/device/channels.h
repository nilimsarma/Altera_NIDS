#ifndef CHANNELS_H
#define CHANNELS_H

#ifdef ONLY_EDIT

//pre_parser

channel rx_channel_data_t inputChannel_0;	//  __attribute__((io("eth0_in")));
channel tx_channel_data_t outputChannel_0;	// __attribute__((io("eth0_out")));
channel rx_channel_data_t inputChannel_1;	//  __attribute__((io("eth1_in")));
channel tx_channel_data_t outputChannel_1;	// __attribute__((io("eth1_out")));

//parser

channel data_stream_t ch_data_stream[NUM_PROTOCOLS]; 	//	__attribute__((depth(0)));
channel bool ch_end_of_pkt			[NUM_PROTOCOLS];	 // __attribute__((depth(0)));

//hash

channel hash_intf_in_t   ch_hash_intf_in; 	// __attribute__((depth(0))); 
channel hash_intf_out_t  ch_hash_intf_out; 	// __attribute__((depth(0))); 

//stream reassembly

channel eth_hdr_struct 	ch_eth_hdr;		// __attribute__((depth(0)));
channel ipv4_hdr_struct ch_ipv4_hdr; 	//	__attribute__((depth(0)));
channel tcp_hdr_struct 	ch_tcp_hdr;		// __attribute__((depth(0)));

channel tcp_inspect_data_flow_t ch_tcp_inspect_data_flow;		// __attribute__((depth(0)));

channel tcp_segment_struct_t ch_tcp_segment;		// __attribute__((depth(0)));


#else

//pre_parser
channel rx_channel_data_t inputChannel_0  __attribute__((io("eth0_in")));
channel tx_channel_data_t outputChannel_0 __attribute__((io("eth0_out")));
channel rx_channel_data_t inputChannel_1  __attribute__((io("eth1_in")));
channel tx_channel_data_t outputChannel_1 __attribute__((io("eth1_out")));

//parser
channel data_stream_t ch_data_stream[NUM_PROTOCOLS]		__attribute__((depth(0)));
channel bool ch_end_of_pkt			[NUM_PROTOCOLS]		__attribute__((depth(0)));

//hash
channel hash_intf_in_t   ch_hash_intf_in	__attribute__((depth(0))); 
channel hash_intf_out_t  ch_hash_intf_out	__attribute__((depth(0))); 

//stream reassembly
channel eth_hdr_struct 	ch_eth_hdr		__attribute__((depth(0)));
channel ipv4_hdr_struct ch_ipv4_hdr		__attribute__((depth(0)));
channel tcp_hdr_struct 	ch_tcp_hdr		__attribute__((depth(0)));

channel tcp_inspect_data_flow_t ch_tcp_inspect_data_flow	__attribute__((depth(0)));
channel tcp_segment_struct_t ch_tcp_segment		__attribute__((depth(0)));

#endif

#endif //CHANNELS_H
