#ifndef HASH_H
#define HASH_H

#define HASH_TBL_MEM_SIZE			NUM_TCP_STREAMS	// 1024
#define HASH_TBL_MEM_INVALID_ADDR	NUM_TCP_STREAMS
#define HASH_TBL_NUM_ROWS	256

typedef uint16_t				hash_node_addr_t;		// 2
typedef uint16_t				hash_row_hdr_addr_t;	// 2
typedef uint16_t				avail_mem_addr_t;		// 2
typedef tcp_stream_hashkey_t	hashkey_t;				// 12
typedef tcp_stream_hash_data_t	hash_data_t;			// 26


typedef enum 
{
	cmd_insert,			//insert
	cmd_delete,			//delete
	cmd_find,			//find only
	cmd_update,			//update
	cmd_hash_done,
	NUM_HASH_CMD
} hash_cmd_t;

#ifdef SIMULATION
__constant char hash_cmd_names[NUM_HASH_CMD][50] = 
{
	"cmd_insert",
	"cmd_delete",
	"cmd_find",	
	"cmd_update",
	"cmd_hash_done"
};
#endif

typedef enum
{
	found,
	inserted,
	deleted,
	success,
	error,

	NUM_HASH_RET
} hash_ret_t;

#ifdef SIMULATION
__constant char hash_ret_names[NUM_HASH_RET][50] = 
{
	"found",
	"inserted",
	"deleted",	
	"success",
	"error"
};
#endif


typedef enum
{
	hash_state_cmd,
	hash_state_insert_0,
	hash_state_insert_1,
	hash_state_insert_2,

	hash_state_delete_0,
	hash_state_delete_1,
	hash_state_delete_2,
	hash_state_delete_3,
	
	hash_state_find_0,
	hash_state_find_1,
	hash_state_find_2,
	hash_state_find_3,
	
	hash_state_update_0,
	hash_state_update_1,
	hash_state_update_2,

	hash_state_write_output,
	NUM_HASH_STATES
} hash_state_t;

char hash_state_names[NUM_HASH_STATES][50] = 
{
	"hash_state_cmd",
	"hash_state_insert_0",
	"hash_state_insert_1",
	"hash_state_insert_2",

	"hash_state_delete_0",
	"hash_state_delete_1",
	"hash_state_delete_2",
	"hash_state_delete_3",
	
	"hash_state_find_0",
	"hash_state_find_1",
	"hash_state_find_2",
	"hash_state_find_3",
	
	"hash_state_update_0",
	"hash_state_update_1",
	"hash_state_update_2",

	"hash_state_write_output"
};

typedef struct 
{
	hashkey_t 		 hashkey;			// 12
	hash_data_t 	 hash_data;			// 26
	hash_node_addr_t  hash_addr_next;	// 2
	hash_node_addr_t  hash_addr_prev;	// 2
} hash_node_struct;	// 42 

typedef struct
{
	hash_cmd_t 			cmd; 			 
	hashkey_t 			hashkey; 		 
	hash_data_t 		hash_data; 	 
	hash_node_addr_t	hash_node_addr;

} hash_intf_in_t;

typedef struct
{
	hash_node_addr_t 	hash_node_addr;
	hash_data_t			hash_data;
	hash_ret_t			hash_ret;

} hash_intf_out_t;

#endif
