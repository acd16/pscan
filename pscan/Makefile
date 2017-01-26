SRC = $(wildcard *.cpp)
CC = g++
CFLAGS = -g
LD_FLAGS = -lpcap -lpthread
portScanner: $(SRC)
	$(CC) -o $@ $^ $(CFLAGS) $(LD_FLAGS)

.PHONY :clean

clean :
	rm -f portScanner
