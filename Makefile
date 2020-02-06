CC = gcc

PACKETFLAGS = -lpcap
RULEFLAGS = -lz
BOYERFLAGS = -lm
MYSQLFLAGS= -L/usr/local/mysql/lib -lmysqlclient

PACKETS = packetsniff
RULES = rules
BOYER = boyermoore
RULES = readrules
SCAN = scanpacket
LOG = logpacket
PORTS = port
UPDATE = updatedb
START = startup

all: $(PACKETS) $(UPDATE) 

$(PACKETS): $(PACKETS).c
	$(CC) -o $(PACKETS) $(PACKETS).c $(BOYER).c $(SCAN).c $(LOG).c $(PORTS).c $(RULES).c $(START).c $(PACKETFLAGS) $(BOYERFLAGS) $(MYSQLFLAGS) $(RULEFLAGS)

$(UPDATE): $(UPDATE).c
	$(CC) -o $(UPDATE) $(UPDATE).c $(RULES).c $(MYSQLFLAGS)

clean:
	$(RM) $(PACKETS) $(UPDATE)
