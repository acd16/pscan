#ifndef UDPBUILD
#define UDPBUILD

#include <netinet/udp.h>
#include <netinet/ip.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>

#define BUF_SIZE 512

using namespace std;

class udpBuild{
    int targetPort;
    int buildL3();
    unsigned char * bufPointer;
    struct udphdr udpHeader;
    uint32_t targetIp;
    int protocol;
    uint32_t srcIp;
    uint16_t getChecksumudp(unsigned char *);
	struct DNS_HEADER
	{
		unsigned short id; // identification number

		unsigned char rd :1; // recursion desired
		unsigned char tc :1; // truncated message
		unsigned char aa :1; // authoritive answer
		unsigned char opcode :4; // purpose of message
		unsigned char qr :1; // query/response flag

		unsigned char rcode :4; // response code
		unsigned char cd :1; // checking disabled
		unsigned char ad :1; // authenticated data
		unsigned char z :1; // its z! reserved
		unsigned char ra :1; // recursion available

		unsigned short q_count; // number of question entries
		unsigned short ans_count; // number of answer entries
		unsigned short auth_count; // number of authority entries
		unsigned short add_count; // number of resource entries
	} dnsHeader;
    public:
        int srcPort;
        udpBuild(int, unsigned char *, uint32_t, uint32_t, int);
};

typedef struct udpPseudo{
    uint32_t srcAddr;
    uint32_t dstAddr;
    uint8_t res;
    uint8_t prot;
    uint16_t len;
}upseudo;

#endif
