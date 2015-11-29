#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include <math.h>
#include "CL/opencl.h"
#include "AOCL_Utils.h"
#include "string.h"

#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

using namespace aocl_utils;

//---------------------------------------------------------------------------------------
// ACL runtime configuration
//---------------------------------------------------------------------------------------

typedef u_char 	uint8_t;
typedef u_short uint16_t;
typedef u_int 	uint32_t;
typedef u_long 	uint64_t;

#include "protocols.h"
#include "tcp_reassembly.h"

//#define EMUL_HOST

typedef enum
{
	k_pre_parser,
	k_eth_parser,
	k_ipv4_parser,
	k_tcp_parser,
	k_tcp_inspect,
	k_tcp_stream_reassembly,
	k_hash_module,
	k_tcp_segment,

	NUM_KERNELS,
	
}	kernel_enum;

#define KERNEL_NAME_MAX_CHARS 40

char kernel_names[NUM_KERNELS][KERNEL_NAME_MAX_CHARS] = 
{
	"pre_parser",
	"eth_parser",
	"ipv4_parser",
	"tcp_parser",
	"tcp_inspect",
	"tcp_stream_reassembly",
	"hash_module",
	"tcp_segment"

};

static cl_platform_id platform = NULL;
static cl_device_id device = NULL;
static cl_context context = NULL;
static cl_command_queue queues[NUM_KERNELS] = {NULL};
static cl_command_queue queue_read = NULL;

static cl_kernel kernel[NUM_KERNELS] = {NULL};
static cl_program program = NULL;
static cl_int status = 0;

//  DATA BUFFERS
//--------------------------------------------------------------------------------------- 

//---------------------------------------------------------------------------------------
//  INIT FUNCTION
//---------------------------
//  1- Find device
//  2- Create context
//  3- Create command queue
//  4- Create/build program
//  5- Create the kernel -- enter kernal name here
//----------------------------------------------------------------------------------------
#define STRING_BUFFER_LEN 1024

bool init() 
{
  if(!setCwdToExeDir()) 
  {
    return false;
  }
  
	// Get the OpenCL platform.
	platform = findPlatform("Altera");
	if(platform == NULL) 
	{
    	printf("ERROR: Unable to find Altera OpenCL platform\n");
    	return false;
	}

	// User-visible output - Platform information
	{
		char char_buffer[STRING_BUFFER_LEN];
		printf("Querying platform for info:\n");
		printf("==========================\n");
		clGetPlatformInfo(platform, CL_PLATFORM_NAME, STRING_BUFFER_LEN, char_buffer, NULL);
		printf("%-40s = %s\n", "CL_PLATFORM_NAME", char_buffer);
		clGetPlatformInfo(platform, CL_PLATFORM_VENDOR, STRING_BUFFER_LEN, char_buffer, NULL);
		printf("%-40s = %s\n", "CL_PLATFORM_VENDOR ", char_buffer);
		clGetPlatformInfo(platform, CL_PLATFORM_VERSION, STRING_BUFFER_LEN, char_buffer, NULL);
		printf("%-40s = %s\n\n", "CL_PLATFORM_VERSION ", char_buffer);
	}

	// Query the available OpenCL devices.
	scoped_array<cl_device_id> devices;
	cl_uint num_devices;

	devices.reset(getDevices(platform, CL_DEVICE_TYPE_ALL, &num_devices));

	// We'll just use the first device.
	device = devices[0];

	// Display some device information.
	//display_device_info(device);

	// Create the context.
	context = clCreateContext(NULL, 1, &device, NULL, NULL, &status);
	checkError(status, "Failed to create context");

	// Create the command queue.
	for(uint8_t i = 0; i<NUM_KERNELS; i++)	
	{
		queues[i] = clCreateCommandQueue(context, device, CL_QUEUE_PROFILING_ENABLE, &status);
		checkError(status, "Failed to create command queue %d", i);
	}

	queue_read = clCreateCommandQueue(context, device, CL_QUEUE_PROFILING_ENABLE, &status);
	checkError(status, "Failed to create command queue queue_read");
		
	// Create the program.
	std::string binary_file = getBoardBinaryFile("snort", device);
	printf("Using AOCX: %s\n\n", binary_file.c_str());
	program = createProgramFromBinary(context, binary_file.c_str(), &device, 1);

	// Build the program that was just created.
	status = clBuildProgram(program, 0, NULL, "", NULL, NULL);
	checkError(status, "Failed to build program");

	// Create the kernel - name passed in here must match kernel name in the
	// original CL file, that was compiled into an AOCX file using the AOC tool
	for(uint8_t i = 0; i<NUM_KERNELS; i++)
	{
		kernel[i] = clCreateKernel(program, kernel_names[i], &status);
		checkError(status, "Failed to create kernel %d", i);
	}

	return true;
}

cl_mem pkt_len_buf;
cl_mem pkt_data_buf;
cl_mem stream_tcp_seg_size_buf;
cl_mem stream_tcp_seg_data_buf;

cl_event kernel_event[NUM_KERNELS];
cl_event write_event[2];
cl_event read_event;

#define MAX_MATCH_COUNT 376

void profile()
{
	for(uint8_t i = 0; i<NUM_KERNELS; i++) 
	{
		clGetProfileInfoAltera(kernel_event[i]);
	}
}

#ifdef EMUL_HOST

#define FILENAME "http_espn.pcap"
#define MAX_PKTS -1

	cl_ulong launch_kernel_producer(uint16_t* pkt_len, uint8_t* pkt_data);
	int pcap_parse(const char* file_name);

	cl_ulong launch_kernels(void)
	{
		
		// Input buffers
		pkt_len_buf = clCreateBuffer(context, CL_MEM_READ_ONLY, sizeof(uint16_t), NULL, &status);
		checkError(status, "Failed to create buffer for pkt_len_buf"); 

		pkt_data_buf = clCreateBuffer(context, CL_MEM_READ_ONLY, MAX_ETH_PKT_LEN_BYTES, NULL, &status);
		checkError(status, "Failed to create buffer for pkt_data_buf");

		stream_tcp_seg_size_buf = clCreateBuffer(context, CL_MEM_READ_WRITE, NUM_TCP_STREAMS*sizeof(stream_tcp_seg_size_t), NULL, &status);
		checkError(status, "Failed to create buffer for stream_tcp_seg_size_buf");

		stream_tcp_seg_data_buf = clCreateBuffer(context, CL_MEM_READ_WRITE, NUM_TCP_STREAMS*sizeof(stream_tcp_seg_data_t), NULL, &status);
		checkError(status, "Failed to create buffer for stream_tcp_seg_data_buf");		

		// Set kernel arguments.
		unsigned argi;

		//send_eth_packet Kernel
		argi = 0;
		status = clSetKernelArg(kernel[k_pre_parser], argi++, sizeof(cl_mem), &pkt_len_buf);
		checkError(status, "Failed to set argument %d on kernel pkt_len_buf", argi - 1);
		status = clSetKernelArg(kernel[k_pre_parser], argi++, sizeof(cl_mem), &pkt_data_buf);
		checkError(status, "Failed to set argument %d on kernel pkt_data_buf", argi - 1);

		argi = 0;
		status = clSetKernelArg(kernel[k_tcp_inspect], argi++, sizeof(cl_mem), &stream_tcp_seg_size_buf);
		checkError(status, "Failed to set argument %d on kernel stream_tcp_seg_size_buf", argi - 1);
		status = clSetKernelArg(kernel[k_tcp_inspect], argi++, sizeof(cl_mem), &stream_tcp_seg_data_buf);
		checkError(status, "Failed to set argument %d on kernel stream_tcp_seg_data_buf", argi - 1);

		argi = 0;		uint32_t max_match_cnt = MAX_MATCH_COUNT;
		status = clSetKernelArg(kernel[k_tcp_segment], argi++, sizeof(uint32_t), &max_match_cnt);
		checkError(status, "Failed to set argument %d on kernel max_match_cnt", argi - 1);

		// Enqueue kernel.
		for(uint8_t k = k_eth_parser; k<NUM_KERNELS; k++) 
		{			
			status = clEnqueueTask(queues[k], kernel[k], 0, NULL, &kernel_event[k]);
			checkError(status, "Failed to launch kernel %s", kernel_names[k]);
		}
		
		//Parse pcap file
		char file_name[] = FILENAME;
		pcap_parse(file_name); 
	}

	cl_ulong launch_kernel_producer(uint16_t* pkt_len, uint8_t* pkt_data, uint32_t pkt_counter)
	{

		// Transfer inputs
		status = clEnqueueWriteBuffer(queues[k_pre_parser], pkt_len_buf, CL_TRUE, 0, sizeof(uint16_t), pkt_len, 0, NULL, &write_event[0]);
		checkError(status, "Failed to write pkt_len_buf");

		status = clEnqueueWriteBuffer(queues[k_pre_parser], pkt_data_buf, CL_TRUE, 0, (*pkt_len), pkt_data, 0, NULL, &write_event[1]);
		checkError(status, "Failed to write pkt_data_buf");

		// Enqueue kernel.
		status = clEnqueueTask(queues[k_pre_parser], kernel[k_pre_parser], 2, write_event, &kernel_event[k_pre_parser]);
		checkError(status, "Failed to launch kernel %s", kernel_names[k_pre_parser]);
		
		clWaitForEvents(2, write_event);		
		clWaitForEvents(1, &kernel_event[k_pre_parser]);
	}

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

		if (handle == NULL) 
		{ 
		  fprintf(stderr,"Couldn't open pcap file %s: %s\n", file_name, errbuf); 
		  return(2); 
		} 

		//----------------- 
		//begin processing the packets in this particular file, one at a time 

		pkt_counter = 0;
		for(;;)	
		{
			int ret = pcap_next_ex(handle, &pkt_header, (const u_char **) &pkt_data);
			
			u_short pkt_len;
			
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
				
				pkt_counter++;		
				launch_kernel_producer(&pkt_len, pkt_data, pkt_counter);
		
				if(pkt_counter == MAX_PKTS)	
				{
					printf("\nMax Packets processed");	fflush(stdout);
					break;
				}
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

#else
	
	cl_ulong launch_kernels(void)
	{

		uint32_t max_match_cnt = MAX_MATCH_COUNT;

		printf("\nstream_tcp_seg_size_t size: %d", sizeof(stream_tcp_seg_size_t));
		printf("\nstream_tcp_seg_data_t size: %d", sizeof(stream_tcp_seg_data_t));
		printf("\n");
		
		stream_tcp_seg_size_buf = clCreateBuffer(context, CL_MEM_READ_WRITE, NUM_TCP_STREAMS*sizeof(stream_tcp_seg_size_t), NULL, &status);
		checkError(status, "Failed to create buffer for stream_tcp_seg_size_buf");

		stream_tcp_seg_data_buf = clCreateBuffer(context, CL_MEM_READ_WRITE, NUM_TCP_STREAMS*sizeof(stream_tcp_seg_data_t), NULL, &status);
		checkError(status, "Failed to create buffer for stream_tcp_seg_data_buf");
		
		// Set kernel arguments.
		unsigned argi;
		argi = 0;
		status = clSetKernelArg(kernel[k_tcp_inspect], argi++, sizeof(cl_mem), &stream_tcp_seg_size_buf);
		checkError(status, "Failed to set argument %d on kernel stream_tcp_seg_size_buf", argi - 1);
		status = clSetKernelArg(kernel[k_tcp_inspect], argi++, sizeof(cl_mem), &stream_tcp_seg_data_buf);
		checkError(status, "Failed to set argument %d on kernel stream_tcp_seg_data_buf", argi - 1);
		
		argi = 0;
		status = clSetKernelArg(kernel[k_tcp_segment], argi++, sizeof(uint32_t), &max_match_cnt);
		checkError(status, "Failed to set argument %d on kernel max_match_cnt", argi - 1);
		
		// Enqueue kernel.
		for(uint8_t k = 0; k<NUM_KERNELS; k++) 
		{
			status = clEnqueueTask(queues[k], kernel[k], 0, NULL, &kernel_event[k]);
			checkError(status, "Failed to launch kernel %s", kernel_names[k]);
		}

	}

#endif

//---------------------------------------------------------------------------------------
//  CLEANUP
//---------------------------
// Free the resources allocated during initialization
//----------------------------------------------------------------------------------------

void cleanup() 
{	
	//free kernel/queue/program/context
	for(uint8_t i = 0; i<NUM_KERNELS; i++) 
	{
		if(kernel[i])
			clReleaseKernel(kernel[i]);		
		if(queues[i])
			clReleaseCommandQueue(queues[i]);
	}	
	if(queue_read)
			clReleaseCommandQueue(queue_read);
	
	if(program)
		clReleaseProgram(program);
	if(context)
		clReleaseContext(context);
	
	if(pkt_len_buf)
		clReleaseMemObject(pkt_len_buf);
	if(pkt_len_buf)
		clReleaseMemObject(pkt_data_buf); 
	if(stream_tcp_seg_data_buf)
		clReleaseMemObject(stream_tcp_seg_data_buf); 
	if(stream_tcp_seg_size_buf)
		clReleaseMemObject(stream_tcp_seg_size_buf); 

	//Release events
	clReleaseEvent(write_event[0]);	clReleaseEvent(write_event[1]);
	clReleaseEvent(read_event);
	for(uint8_t i = 0; i<NUM_KERNELS; i++) 
	{
		clReleaseEvent(kernel_event[0]);
	}
}


int main(int argc, char **argv) 
{	
	if(!init()) return false;
	launch_kernels();

	clWaitForEvents(1, &kernel_event[k_tcp_segment]);
	profile();
	
	cleanup();
}
