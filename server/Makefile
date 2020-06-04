CPP      = g++
CC       = gcc
OBJ      = ../common/base64.o dns.o server.o ../common/util.o ../common/udp.o app.o
LINKOBJ  = ../common/base64.o dns.o server.o ../common/util.o ../common/udp.o app.o /usr/lib/x86_64-linux-gnu/libz.a
LIBS     = -lpthread
INCS     = -I../include
CXXINCS  = 
BIN      = NDNS_server
CXXFLAGS = $(CXXINCS) 
CFLAGS   = $(INCS) -g
RM       = rm -f

.PHONY: all all-before all-after clean clean-custom

all: all-before $(BIN) all-after

clean: clean-custom
	${RM} $(OBJ) $(BIN)

$(BIN): $(OBJ)
	$(CC) $(LINKOBJ) -o $(BIN) $(LIBS)

base64.o: ../common/base64.c
	$(CC) -c ../common/base64.c -o ../common/base64.o $(CFLAGS)

dns.o: dns.c
	$(CC) -c dns.c -o dns.o $(CFLAGS)

server.o: server.c
	$(CC) -c server.c -o server.o $(CFLAGS)

util.o: ../common/util.c
	$(CC) -c ../common/util.c -o ../common/util.o $(CFLAGS)

udp.o: ../common/udp.c
	$(CC) -c ../common/udp.c -o ../common/udp.o $(CFLAGS)

app.o: app.c
	$(CC) -c app.c -o app.o $(CFLAGS)