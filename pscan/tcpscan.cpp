#include "include/tcpScan.h"


int startTcpScan(string tcpTarget, int targetPort, int flags, map<string, map<int, vector<string> > > *resultMap, uint32_t srcIp){
    unsigned char pkt[BUF_SIZE] = {0}, rcvBuf[BUF_SIZE] = {0};
    char filter[BUF_SIZE] = {0};
    char localIp[INET_ADDRSTRLEN] = {0};
    int sock=0, optval=1, optval1, rcvBytes, out=0;
    struct sockaddr_in dst = {0};
    pcap_t * handle;
    cout<<"ATLEASE IN"<<endl;
    /*TODO get default gw inf from /proc*/
    //char inf[5] = "eth0";
    inet_ntop(AF_INET, &srcIp, localIp, sizeof(localIp));
    inet_pton(AF_INET, tcpTarget.c_str(), &(dst.sin_addr));

    cout<<" at line 23"<<endl;
    l2Build frame(tcpTarget, pkt, IPPROTO_TCP, srcIp);
    tcpBuild packet(targetPort, flags, pkt, dst.sin_addr.s_addr, srcIp, IPPROTO_TCP);
    cout<<" at line 26"<<endl;
    snprintf(filter, sizeof(filter), "src host %s && dst host %s",
            tcpTarget.c_str(), localIp);
    //pcapUtil pcap;
    //handle = setupPcap(filter);
    cout<<"The dreaded "<<handle<<endl;
    if(handle == NULL)
        return -1;
    if((sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP))<0){
        cout<<"Error opening socket"<<endl;
        return -1;
    }
    cout<<"PCAP DONE"<<endl;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval));
    //setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, inf, 4);
    if((out = sendto(sock, pkt, sizeof(struct iphdr)+sizeof(struct tcphdr), 0,
            (struct sockaddr *)&dst, sizeof(dst))) < 0){
        perror("sendto error \n");
    }
    cout <<"packet sent "<<out<<endl;
    sleep(5);
    cout<<"calling getmatch"<<endl;
    unsigned char * match = getMatch(IPPROTO_TCP, packet.srcPort, targetPort);
    if(match == NULL) match = getMatch(IPPROTO_ICMP, packet.srcPort, targetPort);
    processTcpResp(flags, match, tcpTarget, targetPort, resultMap);
}

int processTcpResp(int flags, const u_char * resp, string tcpTarget, int targetPort, map<string, map<int, vector<string> > > *resultMap){
    struct ip *ipHeader = NULL;
    struct icmp *icmpHeader = NULL;
    struct tcphdr *tcpHeader = NULL;
    int prot, code, type;

    string scan_type;
    if(flags & 1<<3) scan_type = "XMAS";
    else if(flags & 1<<0) scan_type = "FIN";
    else scan_type = "NULL";

    if(resp){
	ipHeader = (struct ip*)(resp + ETHER_HDR_LEN);
	prot = ipHeader->ip_p;
	if(prot == IPPROTO_TCP){
	    tcpHeader = (struct tcphdr*)(resp + ETHER_HDR_LEN + sizeof(struct ip));
	    if(tcpHeader->rst){
		  //Mark port as closed
		  (*resultMap)[tcpTarget][targetPort].push_back(scan_type + "(Closed)");
	    }
	}
	else if(prot == IPPROTO_ICMP){
	    icmpHeader = (struct icmp*)(resp + ETHER_HDR_LEN + sizeof(struct ip));
	    code = icmpHeader->icmp_code;
	    type = icmpHeader->icmp_type;
	    if(type == 3){
		if(code == 1 || code == 2 || code == 3 || code == 9 || code == 10 || code == 13){
		    //Mark as filtered
		    (*resultMap)[tcpTarget][targetPort].push_back(scan_type + "(Filtered)");
		}
	    }
	    cout << "code is "<<code<< " type "<< type<<endl;
	}
	else{
	    cout<<"unknown prot"<<endl;
	    return -1;
	}
    }
    else{
	// Lack of response
	//Mark port as open|filtered.
	(*resultMap)[tcpTarget][targetPort].push_back(scan_type + "(Open|Filtered)");
    }
}
