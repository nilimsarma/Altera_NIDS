#ifndef READ_ETH_MAC_H
#define READ_ETH_MAC_H

// rx channel packet structure
typedef struct {
 	uint64_t data;
	uint8_t timer[6];
	uint8_t header[2];
} rx_channel_data_t;

// tx channel packet structure
typedef struct {
	uint64_t data;
	uint8_t header;
	uint8_t filler[7]; // ignore
} tx_channel_data_t;

// MASKS FOR INTERPRETING / ENCODING SOP/EOP/EMPTY BYTES
#define MASK_INVALID_BYTES 		0x1C // first header byte 00011100
#define MASK_START_OF_PACKET 	0x01 // first header byte 00000010
#define MASK_END_OF_PACKET 		0x02 // first header byte 00000001

typedef enum 
{
	pre_parser_state_start,
	pre_parser_state_cont,
	pre_parser_state_end
} pre_parser_state_t;

// QDR & DDR Buffer Location Qualifiers
#define QDR __global __attribute__((buffer_location("QDR")))
#define DDR __global __attribute__((buffer_location("DDR")))

#endif
