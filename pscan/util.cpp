#include "include/loop.h"

extern plist * headpkt;
extern int pktCountVal;

void printList(){
    int num = pktCountVal;
    plist * temp = headpkt;
    int prot;
    struct ip * ipHeader;
    for (int i=0;i<num;i++){
       temp = temp->next;
       if(temp == NULL)
           break;
       ipHeader = (struct ip*)(temp->pkt + ETHER_HDR_LEN);
       prot = ipHeader->ip_p;
       cout<<"prot is "<<prot<<endl;
    }
}

unsigned char * getMatch(int prot, int dstPort, int srcPort){
    int num = pktCountVal;
    plist * temp = headpkt;
    int pt;
    struct ip * ipHeader;
    struct tcphdr * tcpHeader;
    struct udphdr * udpHeader;
    cout<<"in find match with "<<num<< ", prot: " << prot << endl;
    for (int i=0;i<num;i++){
        if(temp == NULL)
            break;
        ipHeader = (struct ip*)(temp->pkt + ETHER_HDR_LEN);
        pt = ipHeader->ip_p;
        if(pt == prot){
            if((prot == IPPROTO_TCP)){
                tcpHeader = (struct tcphdr*)(temp->pkt + ETHER_HDR_LEN + sizeof(struct ip));
                if((ntohs(tcpHeader->source) == srcPort) &&
                        ntohs(tcpHeader->dest) == dstPort){
                    return temp->pkt;
                }
            }
            if(prot == IPPROTO_UDP){
                udpHeader = (struct udphdr*)(temp->pkt + ETHER_HDR_LEN + sizeof(struct ip));
                if((ntohs(udpHeader->source) == srcPort) &&
                        ntohs(udpHeader->dest) == dstPort){
                    return temp->pkt;
                }
            }
            if(prot == IPPROTO_ICMP){
                cout << "IPPROTO_ICMP  branch" << endl;
                ipHeader = (struct ip*)(temp->pkt + ETHER_HDR_LEN + sizeof(struct ip) + 8);
                pt = ipHeader->ip_p;
                if((pt == IPPROTO_TCP) || (pt == IPPROTO_UDP)){
                    tcpHeader = (struct tcphdr*)(temp->pkt + ETHER_HDR_LEN + sizeof(struct ip) + 8 + sizeof(struct ip));
                    if((ntohs(tcpHeader->source) == dstPort) &&
                            ntohs(tcpHeader->dest) == srcPort){
                        cout << "OUR Port matches" << endl;
                        return temp->pkt;
                    }
                    else{
                        cout << ntohs(tcpHeader->source) << ":" << srcPort << ":" << ntohs(tcpHeader->dest) << ":" << dstPort << endl;
                    }
                }
            }
        }
        cout<<"prot is "<<pt<<endl;
        temp = temp->next;
    }
    return NULL;
}

void freeList(){
	pktCountVal = 0;
    plist * temp = headpkt;
    if(!headpkt)
        return;
    while(headpkt){
        temp = headpkt->next;
        free(headpkt->pkt);
	    delete(headpkt);
        headpkt = temp;
    }
    headpkt = NULL;
}

