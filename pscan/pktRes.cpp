#include "include/pktRes.h"

pktRes::pktRes(unsigned char* _pkt){
    pkt = _pkt;
}

int pktRes::checkResp(){
    int res = checkProt();
}

int pktRes::checkProt(){

}
