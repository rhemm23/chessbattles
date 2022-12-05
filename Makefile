INC=-I./include
LNK=-lssl -lcrypto
SRC=$(wildcard *.c)

BIN=bin/
ISTL=/services/
SERVICE=server

bin/server: $(SRC)
	mkdir -p $(BIN)
	gcc -o $@ $(SRC) $(INC) $(LNK)

install: bin/server
	mkdir -p $(ISTL)
	systemctl stop $(SERVICE)
	rm -f $(ISTL)server
	cp $^ $(ISTL)
	systemctl start $(SERVICE)
	systemctl status $(SERVICE)

clean:
	rm -rf $(BIN)
