all: clean ipscanner

ipscanner: main.c 
	gcc -o ipscanner main.c fill_packet.h fill_packet.c -w
clean:
	-rm ipscanner