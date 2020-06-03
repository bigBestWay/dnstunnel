CPP      = g++
CC       = gcc
OBJ      = ../base64.o ../dns.o server.o ../util.o ../udp.o ../app.o
LINKOBJ  = ../base64.o ../dns.o server.o ../util.o ../udp.o ../app.o
LIBS     = -lpthread
INCS     = -I../
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

base64.o: ../base64.c
	$(CC) -c ../base64.c -o ../base64.o $(CFLAGS)

dns.o: ../dns.c
	$(CC) -c ../dns.c -o ../dns.o $(CFLAGS)

server.o: server.c
	$(CC) -c server.c -o server.o $(CFLAGS)

util.o: ../util.c
	$(CC) -c ../util.c -o ../util.o $(CFLAGS)

udp.o: ../udp.c
	$(CC) -c ../udp.c -o ../udp.o $(CFLAGS)

app.o: ../app.c
	$(CC) -c ../app.c -o ../app.o $(CFLAGS)