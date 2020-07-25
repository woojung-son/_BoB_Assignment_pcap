all: pcap-test

pcap-test: pcap-test.o
	g++ -o pcap-test pcap-test.o -lpcap

pcap-test.o: pcap-test.cpp
	g++ -c -o pcap-test.o pcap-test.cpp -std=gnu++0x -lpcap

clean: 
	rm -f pcap-test*.o
