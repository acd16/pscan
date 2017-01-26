#ifndef STDSER
#define STDSER

#include<iostream>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<string.h>

using namespace std;

class stdSer{
    string targetIp;
    int httpTest();
    int sshTest();
    int smtpTest();
    int popTest();
    int imapTest();
    int whoisTest();
    int getFromServer(int , char *, char *);
    public:
        stdSer(string);
        int scan();
};

#endif
