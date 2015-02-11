CC = gcc
CFLAGS = -g -W -Wall -pthread
BIN = multithreaded_p2p
OBJS = server_thread.o client_thread.o main.o

all: $(BIN)

debug: CFLAGS += -DDEBUG
debug: clean $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $(BIN) $^

main.o: main.c
	$(CC) $(CFLAGS) -c $^ -o $@

server_thread.o: server_thread.c
	$(CC) $(CFLAGS) -c $^ -o $@

client_thread.o: client_thread.c
	$(CC) $(CFLAGS) -c $^ -o $@

clean:
	rm -f *.o $(BIN)

