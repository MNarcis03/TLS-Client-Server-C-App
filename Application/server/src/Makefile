##############################################
CC=gcc
CFLAGS=
BIN=
C_OBJ_FILES=

##############################################
#CFLAGS+=`pkg-config --cflags --libs glib-2.0`
CFLAGS+=-lssl
CFLAGS+=-lcrypto
CFLAGS+=-pthread
CFLAGS+=-lpthread
CFLAGS+=-Wall
CFLAGS+=-g
CFLAGS+=-w
CFLAGS+=-I ../inc/

##############################################
BIN+=../bin/server

##############################################
C_OBJ_FILES+=main.o
C_OBJ_FILES+=server.o

##############################################
%.o: %.c $(CFLAGS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(BIN): $(C_OBJ_FILES)
	$(CC) -o $(BIN) $(C_OBJ_FILES) $(CFLAGS)

##############################################
all: $(BIN)

##############################################
REMOVE=rm
RFILES=*.o
RFLAGS=

##############################################
RFLAGS+=-rfv

##############################################
clean:
	$(REMOVE) $(RFLAGS) $(BIN) $(RFILES)

##############################################
EXEC=./../bin/server
SERVER_ADDR=127.0.0.1
SERVER_PORT=3000

##############################################
run: $(BIN)
	$(EXEC) $(SERVER_ADDR) $(SERVER_PORT)
