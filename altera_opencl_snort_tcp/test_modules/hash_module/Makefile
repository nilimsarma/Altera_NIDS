CC=g++
CFLAGS=-I.
DEPS = 
OBJ = hash.o hash_utils.o
LIBS=
TARGET = hash_test

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)	$(LIBS)
	
clean: 
	rm -rf *.o $(TARGET)

run: 
	./$(TARGET)
