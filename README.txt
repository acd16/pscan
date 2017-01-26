Adithya Raju(adiyavan)
portScanner

File contents : 

setup.cpp - has the argument parsing code.
l2Build.cpp - builds the network layer of packet.
tcpBuild.cpp - builds tcp header of packet
udpBuild.cpp - builds udp header of packet.
*Scan.cpp - runs respective scan type
loop.cpp - code for handling pcap library.
util.cpp - utils for pcap lib.

Compilation:
cd pscan/
make
./portScanner [options]

Accomplishments :

-> Understood working of raw sockets and packet building.
-> How checksums work
-> Multithreading, synchronization among threads.
-> How port scanning works.

Credits:
cplusplus.com
glibc pthreads documentation
stackoverflow.com
