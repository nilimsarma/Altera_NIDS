#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define MAX_ETH_PKT_LEN_BYTES 1536
#define FILENAME "http_espn.pcap"
#define MAX_PKTS 100

int main () 
{
	const char* file_name = FILENAME;
	
	struct pcap_pkthdr *pkt_header;
	u_char *pkt_data;
	u_int i;
	
	//----------------- 
	//open the pcap file 
	pcap_t *handle; 
	char errbuf[PCAP_ERRBUF_SIZE]; //not sure what to do with this, oh well 
	handle = pcap_open_offline(file_name, errbuf);   //call pcap library function 

	if (handle == NULL) 
	{ 
	  fprintf(stderr,"Couldn't open pcap file %s: %s\n", file_name, errbuf); 
	  return(2); 
	} 

	//----------------- 
	//begin processing the packets in this particular file, one at a time 
	
	for(;;)	
	{
		int ret = pcap_next_ex(handle, &pkt_header, (const u_char **) &pkt_data);
		
		int pkt_len;
		
		if(ret == 1)	//packet read successfully
		{	
			if(pkt_header->caplen != pkt_header->len)	
			{	
				printf("\nPacket len != Capture len. Skipping packet !!!");		
				fflush(stdout);
			}
			else
			{
				pkt_len = pkt_header->len;
			}	
			if(pkt_len > MAX_ETH_PKT_LEN_BYTES)
			{
				printf("\npkt_len > MAX_ETH_PKT_LEN_BYTES");
				pkt_len = MAX_ETH_PKT_LEN_BYTES;
			}
		
			printf("%04x ", pkt_len);
			for(i=0; i < pkt_len; i++)	printf("%02x ",pkt_data[i]);
			printf("\n");
		}
		
		else if (ret == -2)		//no more packets found
		{	
			printf("\nEnd of pcap file reached");	fflush(stdout);
			break;
		}
		else 
		{
			printf("\nError in reading packet");	fflush(stdout);
			break;
		}
	}

	pcap_close(handle);  //close the pcap file 
  //---------- Done with Main Packet Processing Loop --------------  
  return 0; //done
} //end of function