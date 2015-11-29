CC=gcc
CFLAGS=-I.
DEPS = 
OBJ = pcap_parse.o
LIBS=-lpcap
TARGET = pcap_parse

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(TARGET): $(OBJ)
	gcc -o $@ $^ $(CFLAGS)	$(LIBS)
	
clean: 
	rm -rf *.o $(TARGET)

run: 
	./$(TARGET)
