#ifndef LOOP_HEAD
#define LOOP_HEAD

#include <iostream>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <limits.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>

using namespace std;

typedef struct list{
    unsigned char * pkt;
    int len;
    struct list * next;
}plist;

void *pcapfunc(void *);
void parseCallback(unsigned char * user, const struct pcap_pkthdr * h,
                const unsigned char* bytes);
void printList();
int startPcapThread(pthread_t &tid, string ip);
void freeList();
unsigned char * getMatch(int prot, int dstPort, int srcPort);


#endif
