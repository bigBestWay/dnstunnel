CPP      = g++
CC       = gcc
OBJ      = ../common/base32.o dns.o client.o ../common/util.o ../common/udp.o app.o cmd.o 
LINKOBJ  = ../common/base32.o dns.o client.o ../common/util.o ../common/udp.o app.o cmd.o /usr/lib/x86_64-linux-gnu/libz.a
LIBS     = 
INCS     = -I../include
CXXINCS  = 
BIN      = NDNS_client
CXXFLAGS = $(CXXINCS) 
CFLAGS   = $(INCS) -Wall
ifeq ($(debug),yes)
CFLAGS   += -g -DDEBUG=1
endif
LDFLAGS  = -static -Wl,--as-needed -Wl,--exclude-libs=ALL
RM       = rm -f

.PHONY: all all-before all-after clean clean-custom

all: all-before $(BIN) all-after

clean: clean-custom
	${RM} $(OBJ) $(BIN)

$(BIN): $(OBJ)
	$(CC) $(LDFLAGS) $(LINKOBJ) -o $(BIN) $(LIBS)

base32.o: ../common/base32.c
	$(CC) -c ../common/base32.c -o ../common/base32.o $(CFLAGS)

dns.o: dns.c
	$(CC) -c dns.c -o dns.o $(CFLAGS)

client.o: client.c
	$(CC) -c client.c -o client.o $(CFLAGS)

util.o: ../common/util.c
	$(CC) -c ../common/util.c -o ../common/util.o $(CFLAGS)

udp.o: ../common/udp.c
	$(CC) -c ../common/udp.c -o ../common/udp.o $(CFLAGS)

app.o: app.c
	$(CC) -c app.c -o app.o $(CFLAGS)

cmd.o: cmd.c
	$(CC) -c cmd.c -o cmd.o $(CFLAGS)

