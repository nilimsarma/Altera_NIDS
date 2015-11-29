#ifndef TCP_REASSEMBLY_H
#define TCP_REASSEMBLY_H

#define NUM_TCP_STREAMS			1024
#define NUM_SLOTS_PER_STREAM	4

#define ACK_FLAG_MASK	0x10
#define RST_FLAG_MASK	0x04
#define SYN_FLAG_MASK	0x02
#define FIN_FLAG_MASK	0x01

typedef struct
{
	uint32_t seq_num_exp[2]; /*dir 0,1 */				// 8 - expected sequence number
	uint32_t seq_num_slot[NUM_SLOTS_PER_STREAM];	// 16 - seq number of each slot, 4 slots per stream
	uint16_t seg_len_slot[NUM_SLOTS_PER_STREAM];	// 8 - tcp segment length of stored packets
	uint8_t  slot_dir_valid;	 					// 1 - valid and dir values for 4 slots
	uint8_t  stream_state;	 						// 1 - stream state
}	tcp_stream_hash_data_t;						// 34

//slot_dir_valid code: bits 1,0 -> 00: invalid, 01:valid with dir 0, 11:valid with dir 1, 10:don't care

typedef struct {
	uint16_t size[NUM_SLOTS_PER_STREAM];					// size in num of 4 bytes
}	stream_tcp_seg_size_t;

typedef struct {
	uint32_t data[NUM_SLOTS_PER_STREAM][MAX_TCP_SEG_LEN_BYTES/4];	// 4 bytes every cycle
}	stream_tcp_seg_data_t;

//__global stream_data_t stream_data[NUM_TCP_STREAMS];		//5888 * 1024 = 5888 KB = 5 MB

typedef struct
{
	uint32_t  	ip_1;			// 4
	uint32_t  	ip_2;			// 4
	uint16_t 	tcp_port_1;		// 2
	uint16_t 	tcp_port_2;		// 2
	
}tcp_stream_hashkey_t;		// 12

typedef enum {
	closed,
	syn,
	syn_ack,
	open,
	
	fin_1_ack_0_dir_0,
	fin_1_ack_1_dir_0,
	fin_2_ack_1_dir_0,
	
	fin_1_ack_0_dir_1,
	fin_1_ack_1_dir_1,
	fin_2_ack_1_dir_1,
	
	NUM_STREAM_STATES
} stream_state_t;

#ifdef EMUL
__constant char stream_state_names[NUM_STREAM_STATES][50] = 
{
	"closed",
	"syn,",
	"syn_ack",
	"open",
	
	"fin_1_ack_0_dir_0",
	"fin_1_ack_1_dir_0",	
	"fin_2_ack_1_dir_0",
	
	"fin_1_ack_0_dir_1",
	"fin_1_ack_1_dir_1",
	"fin_2_ack_1_dir_1",
};

#endif

typedef enum
{
	state_read_eth,
	state_read_ipv4,
	state_read_tcp,
	state_read,
	
	state_update,
	state_update_1,
	
	state_tcp_inspect_data_flow,
	state_chk_slot_pkt_dir_0,
	state_chk_slot_pkt_dir_1,

	state_hash_module_write,
	state_hash_module_read,
	
	NUM_TCP_REASSEMBLY_STATES
} tcp_reassembly_state_t;

#ifdef EMUL
__constant char tcp_reassembly_state_names[NUM_TCP_REASSEMBLY_STATES][50] = 
{
	"state_read_eth",
	"state_read_ipv4",
	"state_read_tcp",
	"state_read",
	
	"state_update",
	"state_update_1",
	
	"state_tcp_inspect_data_flow",
	"state_chk_slot_pkt_dir_0",
	"state_chk_slot_pkt_dir_1",

	"state_hash_module_write",
	"state_hash_module_read",
};
#endif

typedef enum
{
	cmd_pass_through,
	cmd_write_packet,
	cmd_read_packet,
	
	NUM_TCP_INSPECT_CMD
	
} tcp_inspect_cmd_t;

#ifdef EMUL
__constant char tcp_inspect_cmd_names[NUM_TCP_INSPECT_CMD][50] = 
{
	"cmd_pass_through",
	"cmd_write_packet",
	"cmd_read_packet"
};
#endif

typedef struct
{
	tcp_inspect_cmd_t	tcp_inspect_cmd;
	uint16_t			tcp_stream_addr;
	uint8_t 			slot;	
	bool				dir;
} tcp_inspect_data_flow_t;

typedef struct
{
	tcp_stream_hashkey_t	tcp_stream_hashkey;
	uint16_t				tcp_seg_len;
}tcp_segment_struct_t;

#endif
