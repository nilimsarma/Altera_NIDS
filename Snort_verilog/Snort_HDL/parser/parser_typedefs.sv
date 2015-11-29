`ifndef PARSER_TYPEDEFS_SV
`define PARSER_TYPEDEFS_SV

package PARSER_TYPEDEFS_P;

typedef enum
{
	HEADER_INIT,				
	HEADER_START,				//start header extraction
	HEADER_CONT,				//continue header extraction
	HEADER_END_PAYLOAD, 		//end header extraction, start payload extraction
	HEADER_END,					//end header extraction, payload or variable options starts in next window
	HEADER_END_OPTIONS,			//end header extraction, variable options etc starts which we donot parse
	HEADER_OPTIONS_CONT,		//pass over header options
	HEADER_OPTIONS_END_PAYLOAD, //variable options end, payload starts
	PAYLOAD,					//extract payload
	UNKNOWN					//unknown data, wait till end of packet
} parser_state;

typedef enum
{
	ETH = 0,
	IPV4,
	TCP,
	UDP,
	HTTP,
	TCP_INSPECT,
	TCP_SEGMENT,
	TCP_PAYLOAD,
	NUM_PROTOCOLS
	
}protocol_type;

endpackage

`endif
