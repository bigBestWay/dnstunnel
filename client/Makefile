CPP      = g++
CC       = gcc
OBJ      = ../base64.o ../dns.o client.o ../util.o ../udp.o ../app.o ../cmd.o
LINKOBJ  = ../base64.o ../dns.o client.o ../util.o ../udp.o ../app.o ../cmd.o
LIBS     = 
INCS     = -I../
CXXINCS  = 
BIN      = NDNS_client
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

client.o: client.c
	$(CC) -c client.c -o client.o $(CFLAGS)

util.o: ../util.c
	$(CC) -c ../util.c -o ../util.o $(CFLAGS)

udp.o: ../udp.c
	$(CC) -c ../udp.c -o ../udp.o $(CFLAGS)

app.o: ../app.c
	$(CC) -c ../app.c -o ../app.o $(CFLAGS)

cmd.o: ../cmd.c
	$(CC) -c ../cmd.c -o ../cmd.o $(CFLAGS)