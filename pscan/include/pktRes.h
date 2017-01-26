#include <iostream>

class pktRes{
    unsigned char * pkt;
    int checkProt();
    public:
        pktRes(unsigned char *);
        int checkResp();
};
