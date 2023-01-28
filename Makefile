CFLAGS=-O2 -std=c11 -Wall -Wextra -ggdb
LDFLAGS=-lmodbus -ljson-c
all: modbus

modbus: modbus.o timespec.o
	$(CC) -o $@ $^ $(LDFLAGS)

%.o:	%.c Makefile
	$(CC) $(CFLAGS) -c -o $@ $<
