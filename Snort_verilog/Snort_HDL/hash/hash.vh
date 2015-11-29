`ifndef HASH_VH
`define HASH_VH

`include "tcp_reassembly/tcp_reassembly.vh"

`define HASH_TBL_MEM_SIZE			`NUM_TCP_STREAMS	// 1024
`define HASH_TBL_MEM_INVALID_ADDR	`NUM_TCP_STREAMS
`define HASH_TBL_NUM_ROWS			256
`define AVAIL_MEM_ADDR_EMPTY 		16'hFFFF

`endif
