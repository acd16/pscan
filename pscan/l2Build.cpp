#include "include/l2Build.h"

l2Build::l2Build(string ip, unsigned char * buf, int prot, uint32_t _srcIp){
    targetIp = ip;
    bufPointer = buf;
    srcIp = _srcIp;
    protocol = prot;
    buildL2();
}

int l2Build::buildL2(){
    /*TODO l2 construct as separate class for re-usability*/
    struct sockaddr_in sa = {0}, da = {0};
    //l2header = (struct iphdr *)malloc(sizeof(struct iphdr));
    //l2header = (struct ipheader*)bufPointer;
    memset(&l2header, sizeof(struct iphdr), 0);
    l2header.ihl = 5;
    l2header.version = 4;
    //l2header->tos = 16;
    l2header.tot_len = htons(sizeof(struct iphdr));
    l2header.id = htons(32305);
    l2header.ttl = 64;
    l2header.frag_off = 0;
    l2header.protocol = protocol;
    l2header.saddr = srcIp;
    inet_pton(AF_INET, targetIp.c_str(), &(sa.sin_addr));
    //memcpy(&l2header.daddr, &(sa.sin_addr), sizeof(u_int32_t));
    l2header.daddr = sa.sin_addr.s_addr;
    memcpy(bufPointer, &l2header, sizeof(l2header));
    l2header.check = htons(getChecksum(bufPointer));
    memcpy(bufPointer, &l2header, sizeof(l2header));
    //free(l2header);
}

uint16_t l2Build::getChecksum(unsigned char * buf){
    int numWords = sizeof(struct iphdr)/sizeof(uint16_t);
    uint16_t word = 0;
    uint32_t sum = 0;
    int j=0;
    for(int i=0;i<numWords;i=i+2){
        word = (uint16_t)(buf[i]<<8) | buf[i+1];
        sum += word;
    }
    while(sum>>16)
        sum = (sum & 0xFFFF) + sum>>16;
    return (uint16_t)~sum;
}
