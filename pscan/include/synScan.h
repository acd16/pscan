#ifndef SYNSCAN
#define SYNSCAN

#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <stdio.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include "tcpBuild.h"
#include "l2Build.h"
#include "pcapUtil.h"
#include "loop.h"

using namespace std;

/*class synScan{
    string tcpTarget;
    pcap_t * scanHandle;
    int targetPort;
	map<string, map<int, vector<string> > > *resultMap;
	string key;
    uint32_t srcIp;
    int startScan();
    int setupPcap(string);
    int processResp(const u_char *);
    public:
        synScan(string, int, map<string, map<int, vector<string> > > *, uint32_t);
        int scan();
};*/

int startSynScan(string tcpTarget, int targetPort,
        map<string, map<int, vector<string> > > *resultMap, uint32_t srcIp);
int processSynResp(const u_char * resp, string tcpTarget, int targetPort,
        map<string, map<int, vector<string> > > *resultMap);

#endif
