#include "include/tcpBuild.h"

tcpBuild::tcpBuild(int port, int flags, unsigned char * buf, uint32_t ip, uint32_t _srcIp, int prot){
    targetPort = port;
    tcpFlags = flags;
    bufPointer = buf;
    targetIp = ip;
    srcIp = _srcIp;
    protocol = prot;
    buildL3();
}

int tcpBuild::buildL3(){
    int res=0;
    int seq = rand()%100 + 1;
    memset(&tcpheader, 0, sizeof(tcphdr));
     srand(time(NULL));
     //Choosing random value from ephermal ports.
     res = rand()%(65535-49152) + 49152;
    tcpheader.source = htons(res);
    srcPort = res;
    tcpheader.dest = htons(targetPort);
    tcpheader.seq = htonl(seq);
    //tcpheader.th_off = sizeof(tcpheader)/4;
    tcpheader.doff= 5;
    tcpheader.syn = (tcpFlags & 1<<1) ? 1:0;
	tcpheader.fin = (tcpFlags & 1<<0) ? 1:0;
	tcpheader.ack = (tcpFlags & 1<<4) ? 1:0;
	tcpheader.psh = (tcpFlags & 1<<3) ? 1:0;
	tcpheader.urg = (tcpFlags & 1<<5) ? 1:0;
    tcpheader.window = htons(17520);
    unsigned char pseudoBuf[32] = {0};
    pseudo chkHeader = {0};
    chkHeader.srcAddr = srcIp;
    chkHeader.dstAddr = targetIp;
    chkHeader.prot = protocol;
    chkHeader.len = htons(sizeof(tcpheader));
    memcpy(pseudoBuf, &chkHeader, sizeof(chkHeader));
    memcpy(pseudoBuf+12, &tcpheader, sizeof(tcpheader));
    //memcpy(bufPointer+sizeof(struct iphdr), &tcpheader, sizeof(struct tcphdr));
    //tcpheader.check = (checksum(pseudoBuf));
    tcpheader.check = (getChecksumtcp(pseudoBuf));
    cout<<"tcp cksum "<<htons(tcpheader.check);
    memcpy(bufPointer+sizeof(struct iphdr), &tcpheader, sizeof(struct tcphdr));
    return 0;
}

uint16_t  tcpBuild::getChecksumtcp(unsigned char *buf) {
    uint32_t sum = 0;
    uint16_t * p = (uint16_t *)buf;
    int numWords = (sizeof(struct tcphdr)+sizeof(pseudo))/sizeof(uint16_t);
    for(int j=0;j<numWords;j++)  {
        sum += *p;
        p++;
    }
    while (sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);

    return (uint16_t)~sum;
}
