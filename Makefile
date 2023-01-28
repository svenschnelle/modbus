CFLAGS=-O2 -std=c11 -Wall -Wextra -ggdb -DSYSTEMD
LDFLAGS=-lmodbus -ljson-c -lsystemd
all: modbus

modbus: modbus.o timespec.o
	$(CC) -o $@ $^ $(LDFLAGS)

%.o:	%.c Makefile
	$(CC) $(CFLAGS) -c -o $@ $<
