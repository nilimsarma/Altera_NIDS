CC=g++
CFLAGS=-I.
DEPS = 
OBJ = stream_state.o
LIBS=
TARGET = stream_state

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)	$(LIBS)
	
clean: 
	rm -rf *.o $(TARGET)

run: 
	./$(TARGET)
