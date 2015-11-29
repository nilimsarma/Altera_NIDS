#pragma OPENCL EXTENSION cl_altera_channels : enable

//#define	EMUL
#define SS_UPDATE_MEM

#include "typedefs.h"
#include "protocols.h"
#include "read_eth_mac.h"
#include "parser.h"
#include "tcp_reassembly.h"
#include "hash.h"
#include "channels.h"
#include "stream_state_update_mem.h"

#include "utils.cl"
#include "read_eth_mac.cl"
#include "parser.cl"
#include "tcp_reassembly_utils.cl"
#include "tcp_reassembly.cl"
#include "hash.cl"

