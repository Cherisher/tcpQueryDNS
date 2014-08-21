CC=g++
#CFLAGS=-Wall -g
CFLAGS=-Wall -O2 -lpthread

tcpdns:tcpdns.cpp
	$(CC) -o $@ $< $(CFLAGS)


clean:
	rm tcpdns
