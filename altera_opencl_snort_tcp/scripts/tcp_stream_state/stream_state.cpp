#include <stdio.h>
#include <stdint.h>

//tcp flags
#define ACK_FLAG_MASK	0x10
#define RST_FLAG_MASK	0x04
#define SYN_FLAG_MASK	0x02
#define FIN_FLAG_MASK	0x01

//input
#define MEM_ACK_FLAG_MASK		0x08
#define MEM_RST_FLAG_MASK		0x04
#define MEM_SYN_FLAG_MASK		0x02
#define MEM_FIN_FLAG_MASK		0x01

#define MEM_STREAM_STATE_MASK	0xF0
#define MEM_DIR_MASK			0x100

//output
#define MEM_ERR_MASK			0x01



#define MEM_SIZE 512
uint8_t stream_state_mem[MEM_SIZE];

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
	
	NUM_STATES
} stream_state_t;

void int_to_enum(stream_state_t* stream_state, int x)
{
	switch (x){
		case 0:	*stream_state = closed;				break;
		case 1:	*stream_state = syn;				break;
		case 2:	*stream_state = syn_ack;			break;
		case 3:	*stream_state = open;				break;
		case 4:	*stream_state = fin_1_ack_0_dir_0;	break;
		case 5:	*stream_state = fin_1_ack_1_dir_0;	break;
		case 6:	*stream_state = fin_2_ack_1_dir_0;	break;
		case 7:	*stream_state = fin_1_ack_0_dir_1;	break;
		case 8:	*stream_state = fin_1_ack_1_dir_1;	break;
		case 9:	*stream_state = fin_2_ack_1_dir_1;	break;
		default:	*stream_state = NUM_STATES;		break;
	}
}

void stream_state_update_func(stream_state_t* stream_state, uint8_t* tcp_flags, bool* dir, bool* err)
{
	*err = 1;
	
	if(*stream_state == closed) {
		if( (*tcp_flags & (SYN_FLAG_MASK | ACK_FLAG_MASK | RST_FLAG_MASK | FIN_FLAG_MASK)) == SYN_FLAG_MASK )	//only syn flag	
			{*stream_state = syn; *err = 0;}
	}
	else if(*stream_state == syn) {
		if( (*tcp_flags & (SYN_FLAG_MASK | ACK_FLAG_MASK | RST_FLAG_MASK | FIN_FLAG_MASK)) == (SYN_FLAG_MASK | ACK_FLAG_MASK) )	//syn and ack
			{*stream_state = syn_ack; *err = 0;}
	}
	else if(*stream_state == syn_ack) {
		if( (*tcp_flags & (SYN_FLAG_MASK | ACK_FLAG_MASK | RST_FLAG_MASK | FIN_FLAG_MASK)) == ACK_FLAG_MASK )	//only ack
			{*stream_state = open; *err = 0;}
	}
	else if(*stream_state == open) {
		if( (*tcp_flags & (SYN_FLAG_MASK | RST_FLAG_MASK | FIN_FLAG_MASK)) == FIN_FLAG_MASK )	//only fin, no syn, rst
		{
			if(*dir == 0)	*stream_state = fin_1_ack_0_dir_0;
			else 			*stream_state = fin_1_ack_0_dir_1;

			*err = 0;
		}
		else if( (*tcp_flags & (SYN_FLAG_MASK | RST_FLAG_MASK | FIN_FLAG_MASK)) == 0x00 )	//no syn, rst, fin
		{
			*err = 0;
		}
	}
	else if(*stream_state == fin_1_ack_0_dir_0)	{
		if( ( (*tcp_flags & (SYN_FLAG_MASK | ACK_FLAG_MASK | RST_FLAG_MASK | FIN_FLAG_MASK)) == ACK_FLAG_MASK ) && (*dir == 1) )	//ack for fin 1	
			{*stream_state = fin_1_ack_1_dir_0; *err = 0;}
	}
	else if(*stream_state == fin_1_ack_1_dir_0)	{
		if( ( (*tcp_flags & (SYN_FLAG_MASK | ACK_FLAG_MASK | RST_FLAG_MASK | FIN_FLAG_MASK)) == FIN_FLAG_MASK ) && (*dir == 0) )	//fin 2
			{*stream_state = fin_2_ack_1_dir_0; *err = 0;}
	}
	else if(*stream_state == fin_2_ack_1_dir_0)	{
		if( ( (*tcp_flags & (SYN_FLAG_MASK | ACK_FLAG_MASK | RST_FLAG_MASK | FIN_FLAG_MASK)) == ACK_FLAG_MASK ) && (*dir == 1) )	//ack for fin 2
			{*stream_state = closed; *err = 0;}
	}
	else if(*stream_state == fin_1_ack_0_dir_1)	{
		if( ( (*tcp_flags & (SYN_FLAG_MASK | ACK_FLAG_MASK | RST_FLAG_MASK | FIN_FLAG_MASK)) == ACK_FLAG_MASK ) && (*dir == 0) )	//ack for fin 1
			{*stream_state = fin_1_ack_1_dir_1; *err = 0;}
	}
	else if(*stream_state == fin_1_ack_1_dir_1)	{
		if( ( (*tcp_flags & (SYN_FLAG_MASK | ACK_FLAG_MASK | RST_FLAG_MASK | FIN_FLAG_MASK)) == FIN_FLAG_MASK ) && (*dir == 1) )	//ack for fin 2
			{*stream_state = fin_2_ack_1_dir_1; *err = 0;}
	}
	else if(*stream_state == fin_2_ack_1_dir_1)	{
		if( ( (*tcp_flags & (SYN_FLAG_MASK | ACK_FLAG_MASK | RST_FLAG_MASK | FIN_FLAG_MASK)) == ACK_FLAG_MASK ) && (*dir == 0) )	//ack for fin 2
			{*stream_state = closed; *err = 0;}
	}
}

int main ()
{
	//initialize the memory
	uint16_t input;
	for(input=0; input<MEM_SIZE; input++)	{
		stream_state_mem[input] = input&0xF0;	//err = 0
	}	
	
	//All range of input
	stream_state_t stream_state;
	uint8_t tcp_flags;
	bool dir;
	bool err;
	bool ack_flag, rst_flag, syn_flag, fin_flag;
	
	for(input=0; input<MEM_SIZE; input++)	{
		//stream_state = (input & MEM_STREAM_STATE_MASK)>>4;
		int_to_enum(&stream_state, (input & MEM_STREAM_STATE_MASK)>>4);
		
		dir = ((input & MEM_DIR_MASK) != 0);
		ack_flag = ((input & MEM_ACK_FLAG_MASK) !=0 );
		rst_flag = ((input & MEM_RST_FLAG_MASK) !=0 );
		syn_flag = ((input & MEM_SYN_FLAG_MASK) !=0 );
		fin_flag = ((input & MEM_FIN_FLAG_MASK) !=0 );
		
		tcp_flags = fin_flag | (syn_flag<<1) | (rst_flag<<2) | (ack_flag<<4);
		
		stream_state_update_func(&stream_state, &tcp_flags, &dir, &err);
		
		stream_state_mem[input] = ((stream_state<<4) & MEM_STREAM_STATE_MASK) | (err & MEM_ERR_MASK);
	}
	
	printf("\nstream_state_mem[%d] = {\n", MEM_SIZE, stream_state_mem[0]);
	for(input=0; input<MEM_SIZE; input++)	{
		printf("0x%02x,\n", stream_state_mem[input]);
	}
	printf("};\n");
	return 0;
}