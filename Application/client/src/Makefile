##############################################
CC=gcc
CFLAGS=
BIN=
C_OBJ_FILES=

##############################################
#CFLAGS+=`pkg-config --cflags --libs glib-2.0`
#CFLAGS+=-pthread
#CFLAGS+=-lpthread
CFLAGS+=-I ../inc/
CFLAGS+=-I ../../tls/inc/
CFLAGS+=-Wall
CFLAGS+=-g

##############################################
BIN+=../bin/client

##############################################
C_OBJ_FILES+=main.o
C_OBJ_FILES+=client.o

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
SERVER_ADDR=127.0.0.1
SERVER_PORT=3000
EXEC=./../bin/client

##############################################
run: $(BIN)
	$(EXEC) $(SERVER_ADDR) $(SERVER_PORT)