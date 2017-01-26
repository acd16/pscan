#include "include/pcapUtil.h"

pcap_t * setupPcap(char * filter){
    struct bpf_program bpf = {0};
    char err[BUF_SIZE] = {0}, inf[5] = "eth0";
    int out;
    pcap_t * handle = NULL;
    //cout<<handle<<__LINE__<<endl;
    if((handle = pcap_open_live(inf, 32767, 0, -1, err)) == NULL){
        cout<<"Unable to open pcap handle";
        return NULL;
    }
    cout<<handle<< " GGG "<< filter<<endl;
    if((out = pcap_compile(handle, &bpf, filter, 0, PCAP_NETMASK_UNKNOWN)) <0){
        cout<<"pcap compile fail "<<endl;
        return NULL;
    }
    if((out = pcap_setfilter(handle, &bpf)) <0){
        cout<<"pcap setfilter fail "<<endl;
        return NULL;
    }
    return handle;
}


const u_char * rcvResp(pcap_t * handle){
    struct pcap_pkthdr pktHeader = {0};
    const u_char * resp = NULL;
    //cout<<handle<<__LINE__<<endl;
    resp = pcap_next(handle, &pktHeader);
    return resp;
}

/*pcapUtil::~pcapUtil(){
    cout<<"closing handle"<<endl;
    if(handle)
        pcap_close(handle);
}*/
