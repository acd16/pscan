#include "include/loop.h"

extern plist * headpkt;
extern int pktCountVal;
extern pcap_t * pktHandle;

int startPcapThread(pthread_t &tid, string ip){
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    struct bpf_program bpf = {0};
    char err[PCAP_ERRBUF_SIZE] = {0}, inf[5] = "eth0";
    int out;
    char filter[128] = {0};
    snprintf(filter, sizeof(filter), "tcp or udp or icmp and src host %s", ip.c_str());
    cout<<"IN HERE"<<endl;
    //pcap_t * handle = NULL;
    cout<<pktHandle<<__LINE__<<endl;
    if((pktHandle = pcap_open_live(inf, 32767, 0, -1, err)) == NULL){
        cout<<"Unable to open pcap handle";
        return -1;
    }
    cout<<pktHandle<< " GGG "<< filter<<endl;
    if((out = pcap_compile(pktHandle, &bpf, filter, 0, PCAP_NETMASK_UNKNOWN)) <0){
        cout<<"pcap compile fail "<<endl;
        return -1;
    }
    if((out = pcap_setfilter(pktHandle, &bpf)) <0){
        cout<<"pcap setfilter fail "<<endl;
        return -1;
    }
    pthread_create(&tid, &attr, pcapfunc, NULL);
    sleep(2);
    //printList();
    //pthread_join(tid, NULL);
}

void * pcapfunc(void * arg){
    //pcap_t * handle = (pcap_t *) arg;
    cout<<"LOOP START "<<pktHandle<<endl;
    pcap_loop(pktHandle, INT_MAX, parseCallback, NULL);
}


void parseCallback(unsigned char * user, const struct pcap_pkthdr * h,
        const unsigned char* bytes){
    plist * node = new plist();
    node -> pkt = (unsigned char *)malloc(sizeof(char)*h->len);
    node -> len = h->len;
    if(headpkt == NULL)
        node -> next = NULL;
    else
        node -> next = headpkt;
    memcpy(node->pkt, bytes, h->len);
    headpkt = node;
    pktCountVal++;

    cout << "got packet of len "<<h->len<< " ";
}
