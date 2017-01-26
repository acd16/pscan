#ifndef L2BUILD
#define L2BUILD

#include <iostream>
#include <netdb.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <ifaddrs.h>

using namespace std;

class l2Build{
    string targetIp;
    unsigned char * bufPointer;
    int buildL2();
    u_int16_t getChecksum(unsigned char *);
    struct iphdr l2header;
    int protocol;
    uint32_t srcIp;
    public:
        l2Build(string, unsigned char *, int, uint32_t);
};

#endif
