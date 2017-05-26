CC=g++
#CFLAGS=-Wall -g
CFLAGS=-Wall -O2 -lpthread
CFLAGS += -Wno-unused-but-set-variable

tcpdns:tcpdns.cpp
	$(CC) -o $@ $< $(CFLAGS)


clean:
	rm tcpdns
