CFLAGS=-O2 -std=c11 -Wall -Wextra -ggdb
LDFLAGS=-lmodbus
all: modbus

modbus: modbus.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
