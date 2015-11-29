`ifndef HASH_TYPEDEFS_SV
`define HASH_TYPEDEFS_SV

package HASH_TYPEDEFS_P;
import TYPEDEFS_P::*;
import TCP_REASSEMBLY_TYPEDEFS_P::*;

typedef uint16_t				hash_node_addr_t;		// 2
typedef uint16_t				hash_row_hdr_addr_t;	// 2
typedef uint16_t				avail_mem_addr_t;		// 2
typedef tcp_stream_hashkey_t	hashkey_t;				// 12
typedef tcp_stream_hash_data_t	hash_data_t;			// 34

typedef enum logic [3:0]
{
	cmd_insert,			//insert
	cmd_delete,			//delete
	cmd_find,			//find only
	cmd_update			//update
} hash_cmd_t;

typedef enum logic [3:0]
{
	found,
	inserted,
	deleted,
	success,
	error
} hash_ret_t;

typedef struct 
{
	hashkey_t 		 hashkey;			// 12
	hash_data_t 	 hash_data;			// 34
	hash_node_addr_t  hash_addr_next;	// 2
	hash_node_addr_t  hash_addr_prev;	// 2
} hash_node_struct;	// 50 

typedef struct
{
	hash_cmd_t 			cmd; 			 
	hashkey_t 			hashkey; 		 
	hash_data_t 		hash_data; 	 
	hash_node_addr_t	hash_node_addr;

} hash_cmd_intf_t;

typedef struct
{
	hash_node_addr_t 	hash_node_addr;
	hash_data_t			hash_data;
	hash_ret_t			hash_ret;

} hash_ret_intf_t;

typedef enum
{
	hash_state_init,

	hash_state_cmd,
	hash_state_insert_0,
	hash_state_insert_1,
	hash_state_insert_2,

	hash_state_delete_0,
	hash_state_delete_1,
	hash_state_delete_2,
	hash_state_delete_3,
	hash_state_delete_4,
	hash_state_delete_5,
	
	hash_state_find_0,
	hash_state_find_1,
	hash_state_find_2,
	hash_state_find_3,
	
	hash_state_update_0,
	hash_state_update_1,
	hash_state_update_2,
	
	hash_state_write_output
} hash_state_t;

endpackage

`endif
