CC = g++ -static-libstdc++
CFLAGS = -c -Wall -Wextra
LDFLAGS = -g

SOURCES = ipk-lookup.cpp

CLIENT_OBJECTS = $(SOURCES:.cpp=.o)

CLIENT_EXECUTABLE = ipk-lookup

.PHONY: all client server clean remove

all: client

client: $(CLIENT_EXECUTABLE)
	@echo Created ipk-lookup executable.

$(CLIENT_EXECUTABLE): $(CLIENT_OBJECTS)
	@$(CC) $(LDFLAGS) $(CLIENT_OBJECTS) -o $@

.cpp.o:
	@$(CC) $(CFLAGS) $< -o $@

clean:
	@rm -f *.o
	@echo Object files removed.

remove: clean
	@rm -f $(CLIENT_EXECUTABLE)
	@echo Executables removed.
