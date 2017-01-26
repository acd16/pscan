#ifndef PCAPUTIL
#define PCAPUTIL

#include <iostream>
#include <stdlib.h>
#include <pcap/pcap.h>

#define BUF_SIZE 512

using namespace std;

/*class pcapUtil{
    //pcap_t * handle;
    //char * filter;
    public:
        pcap_t * setupPcap(char *);
        const u_char * rcvResp(pcap_t *);
        //pcapUtil(pcap_t , char *);
        //~pcapUtil();
};*/

pcap_t * setupPcap(char *);
const u_char * rcvResp(pcap_t *);

#endif
