#ifndef READ_ETH_MAC_H
#define READ_ETH_MAC_H

#define ETH_PACKET_SIZE	1536	//8 bytes aligned

// rx channel packet structure
typedef struct client_packet_ {
 	uint64_t data;
	uint8_t timer[6];
	uint8_t header[2];
} client_packet_t;

// tx channel packet structure
typedef struct macphy_packet_ {
	uint64_t data;
	uint8_t header;
	uint8_t filler[7]; // ignore
} macphy_packet_t;

// MASKS FOR INTERPRETING / ENCODING SOP/EOP/EMPTY BYTES
#define MASK_INVALID_BYTES 		0x1C // first header byte 00011100
#define MASK_START_OF_PACKET 	0x01 // first header byte 00000010
#define MASK_END_OF_PACKET 		0x02 // first header byte 00000001

typedef enum 
{
	state_start,
	state_cont,
	state_end
} read_eth_mac_state_t;

#endif
