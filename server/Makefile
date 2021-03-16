CPP      = g++
CC       = gcc
OBJ      = ../common/base32.o log.o ui.o dns.o server.o ../common/util.o ../common/udp.o app.o gateway.o worker.o cmd.o session.o 
LINKOBJ  = ../common/base32.o log.o ui.o dns.o server.o ../common/util.o ../common/udp.o app.o gateway.o worker.o cmd.o session.o /usr/lib/x86_64-linux-gnu/libz.a
LIBS     = -lpthread
INCS     = -I../include
CXXINCS  = 
BIN      = NDNS_server
CXXFLAGS = $(CXXINCS) 
CFLAGS   = $(INCS) -Wall
ifeq ($(debug),yes)
CFLAGS   += -g -DDEBUG=1
endif
RM       = rm -f

.PHONY: all all-before all-after clean clean-custom

all: all-before $(BIN) all-after

clean: clean-custom
	${RM} $(OBJ) $(BIN)

$(BIN): $(OBJ)
	$(CC) $(LINKOBJ) -o $(BIN) $(LIBS)

base32.o: ../common/base32.c
	$(CC) -c ../common/base32.c -o ../common/base32.o $(CFLAGS)

dns.o: dns.c
	$(CC) -c dns.c -o dns.o $(CFLAGS)

server.o: server.c
	$(CC) -c server.c -o server.o $(CFLAGS)

util.o: ../common/util.c
	$(CC) -c ../common/util.c -o ../common/util.o $(CFLAGS)

udp.o: ../common/udp.c
	$(CC) -c ../common/udp.c -o ../common/udp.o $(CFLAGS)

ui.o: ui.c
	$(CC) -c ui.c -o ui.o $(CFLAGS)

log.o: log.c
	$(CC) -c log.c -o log.o $(CFLAGS)

app.o: app.c
	$(CC) -c app.c -o app.o $(CFLAGS)

gateway.o: gateway.c
	$(CC) -c gateway.c -o gateway.o $(CFLAGS)

worker.o: worker.c
	$(CC) -c worker.c -o worker.o $(CFLAGS)

cmd.o: cmd.c
	$(CC) -c cmd.c -o cmd.o $(CFLAGS)

session.o:session.c
	$(CC) -c session.c -o session.o $(CFLAGS)

