#ifndef ACKSCAN
#define ACKSCAN

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

int startAckScan(string tcpTarget, int targetPort,
        map<string, map<int, vector<string> > > *resultMap, uint32_t srcIp);
int processAckResp(const u_char * resp, string tcpTarget, int targetPort,
        map<string, map<int, vector<string> > > *resultMap);

#endif
