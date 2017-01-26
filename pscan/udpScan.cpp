#include "include/udpScan.h"

udpScan::udpScan(string ip, int port, map<string, map<int, vector<string> > > *myResultMap, uint32_t _srcIp){
    udpTarget = ip;
    targetPort = port;
	resultMap = myResultMap;
    srcIp = _srcIp;
}

int udpScan::scan(){

    char filter[BUF_SIZE] = {0};
    pcap_t * handle;
    //char inf[5] = "eth0";
    struct sockaddr_in dst = {0};
    char localIp[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &srcIp, localIp, sizeof(localIp));
    inet_pton(AF_INET, udpTarget.c_str(), &(dst.sin_addr));

    snprintf(filter, sizeof(filter), "src host %s && dst host %s", udpTarget.c_str(), localIp);
    //pcapUtil pcap(handle, filter);
    //pcap.setupPcap();

    if (targetPort == 53){
		unsigned char bufPointer[65536],*qname,*reader;
		unsigned char hostnameDNSformatted[100] = "3www6google3com ";
		int sock;

		struct sockaddr_in a;
		struct sockaddr_in dest;

		struct DNS_HEADER *dns = NULL;
		struct QUESTION *qinfo = NULL;

		sock = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries

		dest.sin_family = AF_INET;
		dest.sin_port = htons(53);
		dest.sin_addr.s_addr = inet_addr(udpTarget.c_str()); //dns servers

		//Set the DNS structure to standard queries
		dns = (struct DNS_HEADER *)&bufPointer;

		dns->id = (unsigned short) htons(getpid());
		dns->qr = 0; 		// This is a query
		dns->opcode = 0; 	// This is a standard query
		dns->aa = 0; 		// Not Authoritative
		dns->tc = 0; 		// This message is not truncated
		dns->rd = 1; 		// Recursion Desired
		dns->ra = 0; 		// Recursion not available
		dns->z = 0;
		dns->ad = 0;
		dns->cd = 0;
		dns->rcode = 0;
		dns->q_count = htons(1); //we have only one question
		dns->ans_count = 0;
		dns->auth_count = 0;
		dns->add_count = 0;

		qinfo =(struct QUESTION*)&bufPointer[sizeof(struct DNS_HEADER)+(strlen((const char*)hostnameDNSformatted)+1)];
		qinfo->qtype = htons(1); // query type A record
		qinfo->qclass = htons(1);

		if( sendto(sock, (char*)bufPointer, sizeof(struct DNS_HEADER) + (strlen((const char*)hostnameDNSformatted)+1)
								+ sizeof(struct QUESTION), 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
			cout << "sendto failed" << endl;
		}

		int szdst = sizeof(dest);
		string scan_type;
		scan_type = "UDP";

		if(recvfrom (sock, (char*)bufPointer , 65536 , 0 , (struct sockaddr*)&dest , (socklen_t*)&szdst ) < 0){
		    cout<<"UDP closed"<<endl;
		    (*resultMap)[udpTarget][targetPort].push_back(scan_type + "(Closed)");
		}
		else{
		     //Mark port as open
		      cout<<"UDP open"<<endl;
			(*resultMap)[udpTarget][targetPort].push_back(scan_type + "(Open)");
		}
    }
    else{
		int sock = 0, optval = 1, out=0;
		unsigned char pkt[BUF_SIZE] = {0};

		l2Build frame(udpTarget, pkt, IPPROTO_UDP, srcIp);
		udpBuild packet(targetPort, pkt, dst.sin_addr.s_addr, srcIp, IPPROTO_UDP);

		if((sock = socket(PF_INET, SOCK_RAW, IPPROTO_UDP))<0){
		cout<<"Error opening socket"<<endl;
		return -1;
		}
		setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval));
		//setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, inf, 4);
		if((out = sendto(sock, pkt, sizeof(struct iphdr)+sizeof(struct udphdr), 0,
		  (struct sockaddr *)&dst, sizeof(dst))) < 0){
			perror("sendto error \n");
		}
		cout <<"UDP packet sent "<<out<<endl;
    sleep(5);
    //processResp(pcap.rcvResp());
    cout<<"calling getmatch"<<endl;
    unsigned char * match = getMatch(IPPROTO_UDP, packet.srcPort, targetPort);
    if(match == NULL) match = getMatch(IPPROTO_ICMP, packet.srcPort, targetPort);
    processResp(match);
    }
 }

int udpScan::processResp(const u_char * resp){
    struct ip *ipHeader = NULL;
    struct icmp *icmpHeader = NULL;
    struct udphdr *udpHeader = NULL;
    int prot, code, type;
	string scan_type;

	scan_type = "UDP";

    if(resp){
        ipHeader = (struct ip*)(resp + ETHER_HDR_LEN);
        prot = ipHeader->ip_p;
        if(prot == IPPROTO_UDP){
            //Mark port as open
            cout<<"UDP open"<<endl;
			(*resultMap)[udpTarget][targetPort].push_back(scan_type + "(Open)");
        }
        else if(prot == IPPROTO_ICMP){
            icmpHeader = (struct icmp*)(resp + ETHER_HDR_LEN + sizeof(struct ip));
            code = icmpHeader->icmp_code;
            type = icmpHeader->icmp_type;
            if(type == 3){
                if(code == 1 || code == 2 || code == 9 || code == 10 || code == 13){
                    //Mark as filtered
                    cout<<"UDP filtered"<<endl;
					(*resultMap)[udpTarget][targetPort].push_back(scan_type + "(Filtered)");
                }
            }
            cout << "code is "<<code<< " type "<< type<<endl;
        }
        else{
            cout<<"unknown prot"<<endl;
            return -1;
        }
        cout<<"GOT IT "<<endl;
    }
    else{
        //Mark port as closed.
        cout<<"UDP closed"<<endl;
		(*resultMap)[udpTarget][targetPort].push_back(scan_type + "(Closed)");
    }
}
