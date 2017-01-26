#ifndef TCPBUILD
#define TCPBUILD

#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define BUF_SIZE 512

using namespace std;

class tcpBuild{
    int targetPort;
    int tcpFlags;
    uint32_t targetIp;
    int protocol;
    uint32_t srcIp;
    unsigned char * bufPointer;
    int buildL3();
    struct tcphdr tcpheader;
    uint16_t getChecksumtcp(unsigned char*);
    public:
        int srcPort;
        tcpBuild (int, int, unsigned char *, uint32_t, uint32_t, int);
};


typedef struct tcpPseudo{
    uint32_t srcAddr;
    uint32_t dstAddr;
    uint8_t res;
    uint8_t prot;
    uint16_t len;
}pseudo;

#endif
