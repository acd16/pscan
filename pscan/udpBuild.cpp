#include "include/udpBuild.h"

udpBuild::udpBuild(int port, unsigned char * buf, uint32_t ip, uint32_t _srcIp, int prot){
    targetPort = port;
    bufPointer = buf;
    targetIp = ip;
    srcIp = _srcIp;
    protocol = prot;
    buildL3();
}

int udpBuild::buildL3(){
    int res=0;
	if (targetPort == 53){ // DNS header
		memset(&dnsHeader, 0, sizeof(struct DNS_HEADER));
		dnsHeader.id = (unsigned short) htons(getpid());
		dnsHeader.qr = 0; 				//This is a query
		dnsHeader.opcode = 0; 			//This is a standard query
		dnsHeader.aa = 0; 				//Not Authoritative
		dnsHeader.tc = 0; 				//This message is not truncated
		dnsHeader.rd = 1; 				//Recursion Desired
		dnsHeader.ra = 0;				//Recursion not available! hey we dont have it (lol)
		dnsHeader.z = 0;
		dnsHeader.ad = 0;
		dnsHeader.cd = 0;
		dnsHeader.rcode = 0;
		dnsHeader.q_count = htons(1); 	//we have only 1 question
		dnsHeader.ans_count = 0;
		dnsHeader.auth_count = 0;
		dnsHeader.add_count = 0;

		memcpy(bufPointer+sizeof(struct DNS_HEADER), &dnsHeader, sizeof(struct DNS_HEADER));
	}
	else{
		memset(&udpHeader, 0, sizeof(struct udphdr));
        //Choosing random value from ephermal ports.
        res = rand()%(65535-49152) + 49152;
		udpHeader.source = htons(res);
        srcPort = res;
		udpHeader.dest = htons(targetPort);
		udpHeader.len = htons(8);
    unsigned char pseudoBuf[32] = {0};
    upseudo chkHeader = {0};
    chkHeader.srcAddr = srcIp;
    chkHeader.dstAddr = targetIp;
    chkHeader.prot = protocol;
    chkHeader.len = htons(8);
    memcpy(pseudoBuf, &chkHeader, sizeof(chkHeader));
    memcpy(pseudoBuf+12, &udpHeader, sizeof(udpHeader));
    //memcpy(bufPointer+sizeof(struct iphdr), &tcpheader, sizeof(struct tcphdr));
    //tcpheader.check = (checksum(pseudoBuf));
    udpHeader.check = (getChecksumudp(pseudoBuf));
    memcpy(bufPointer+sizeof(struct iphdr), &udpHeader, sizeof(struct udphdr));
    return 0;
		//memcpy(bufPointer+sizeof(struct iphdr), &udpHeader, sizeof(struct udphdr));
	}
}

uint16_t  udpBuild::getChecksumudp(unsigned char *buf) {
    uint32_t sum = 0;
    uint16_t * p = (uint16_t *)buf;
    int numWords = (sizeof(struct udphdr)+sizeof(upseudo))/sizeof(uint16_t);
    for(int j=0;j<numWords;j++)  {
        sum += *p;
        p++;
    }
    while (sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);

    return (uint16_t)~sum;
}
