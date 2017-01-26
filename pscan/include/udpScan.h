#ifndef UDPSCAN
#define UDPSCAN

#include "udpBuild.h"
#include "l2Build.h"
#include "pcapUtil.h"
#include "loop.h"
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <unistd.h>
#include <pcap/pcap.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>

using namespace std;

class udpScan{
    string udpTarget;
    pcap_t * scanHandle;
    int targetPort;
	map<string, map<int, vector<string> > > *resultMap;
	string key;
    int processResp(const u_char *);
    uint32_t srcIp;
    //DNS header structure
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
    };

    //Constant sized fields of query structure
    struct QUESTION
    {
		unsigned short qtype;
		unsigned short qclass;
    };

    public:
        udpScan(string, int, map<string, map<int, vector<string> > > *, uint32_t);
        int scan();
};

#endif
