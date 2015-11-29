#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define MAX_PKTS 10
#define FILENAME "http_espn.pcap"
//------------------------------------------------------------------- 
int pcap_parse(const char* file_name) 
{ 
	struct pcap_pkthdr *pkt_header;
	u_char *pkt_data;
	u_int pkt_counter;
	u_int i;
	
	//----------------- 
	//open the pcap file 
	pcap_t *handle; 
	char errbuf[PCAP_ERRBUF_SIZE]; //not sure what to do with this, oh well 
	handle = pcap_open_offline(file_name, errbuf);   //call pcap library function 

	if (handle == NULL) { 
	  fprintf(stderr,"Couldn't open pcap file %s: %s\n", file_name, errbuf); 
	  return(2); 
	} 

	//----------------- 
	//begin processing the packets in this particular file, one at a time 

	pkt_counter = 0;
	for(;;)	{
		printf("\n\n");
		int ret = pcap_next_ex(handle, &pkt_header, (const u_char **) &pkt_data);
		
		u_int pkt_len;
		
		if(ret == 1)	{	//packet read successfully
			
			if(pkt_header->caplen < pkt_header->len)	{pkt_len = pkt_header->caplen;	printf("\nCapture len < Packet len\n");}
			else pkt_len = pkt_header->len;
			
			printf("caplen: %d, len: %d, pkt_len: %d\n", pkt_header->caplen, pkt_header->len, pkt_len);
			for(i=0; i<pkt_len; i++)	printf("%02x ", *(pkt_data+i));
			
			pkt_counter++;
			if(pkt_counter == MAX_PKTS)	{
				printf("\nMax Packets processed");
				break;
			}
		}
		else if (ret == -2)		{	//no more packets found
			printf("\nEnd of pcap file reached");
			break;
		}
		else {
			printf("\nError in reading packet");
			break;
		}
	}

	pcap_close(handle);  //close the pcap file 
  //---------- Done with Main Packet Processing Loop --------------  
  return 0; //done
} //end of function

int main ()	{
	
	char file_name[] = FILENAME;
	pcap_parse(file_name);
	return 0;
}
