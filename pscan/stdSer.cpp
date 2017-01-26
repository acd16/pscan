#include "include/stdSer.h"
#include "sys/time.h"
stdSer::stdSer(string _targetIP){
    targetIp = _targetIP;
}

int stdSer::getFromServer(int port, char * data, char * resp){
    int sock = 0, out = -1;
    struct sockaddr_in dst = {0};
    struct timeval tv = {0};
    if((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0){
        cout << "socket connection failed" <<endl;
        goto done;
    }
    tv.tv_sec = 5;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    inet_pton(PF_INET, targetIp.c_str(), &dst.sin_addr);
    if((out = connect(sock, (struct sockaddr*)&dst, sizeof(dst)))<0){
        cout << "connect failed"<<endl;
        goto done;
    }
    if(data){
        if((out = send(sock, data, strlen(data), 0))<0){
            cout << "send failed"<<endl;
            goto done;
        }
    }
    if((out = recv(sock, resp, 1024, 0))<0){
        cout << "recv failed"<<endl;
        goto done;
    }
    resp[out] = '\0';
    out = 1;
done:
    return out;
}

int stdSer::httpTest(){
    int out = -1;
    char * ref;
    char sendStr[512] = {0}, resp[1024] ={0}, op[512] = {0};
    strncpy(sendStr, "HEAD / HTTP/1.1\r\n\r\n", sizeof(sendStr));
    if((out = getFromServer(80, sendStr, resp))<0){
        goto done;
    }
    if((ref = strstr(resp, "Server")) == NULL){
        cout << "HTTP info unknown"<<endl;
        goto done;
    }
    for(int i=0;i<sizeof(op);i++){
        if(ref[i] == '\n')
            break;
        op[i] = ref[i];
    }

    cout<<"HTTP info: "<<op<<endl;
    out = 1;
done:
    return out;
}

int stdSer::sshTest(){
    int out = -1;
    char resp[1024] = {0};
    if((out = getFromServer(22, NULL, resp))<0){
        cout<<"SSH info unknown"<<endl;
        goto done;
    }
    for(int i=0;i<sizeof(resp);i++){
        if((*(resp+i) == '\n') || (*(resp+i) == '\0')){
            *(resp+i)='\0';
            break;
        }
    }

    cout<<"SSH info: "<<resp<<endl;
    out = 1;
done:
    return out;
}

int stdSer::whoisTest(){
    int out = -1;
    char resp[1024] = {0}, sendStr[512]={0}, op[512]={0};
    char * ref=NULL;
    strncpy(sendStr, "portscan", sizeof(sendStr));
    if((out = getFromServer(43, sendStr, resp))<0){
        cout<<"WHOIS info unknown"<<endl;
        goto done;
    }
    if((ref = strstr(resp, "Server Version")) == NULL){
        cout << "WHOIS info unknown"<<endl;
        goto done;
    }
    for(int i=0;i<sizeof(op);i++){
        if(ref[i] == '\n')
            break;
        op[i] = ref[i];
    }

    cout<<"WHOIS info: "<<op<<endl;
    out = 1;
done:
    return out;
}

int stdSer::smtpTest(){
    int out = -1;
    char resp[1024] = {0}, op[512]={0};
    if((out = getFromServer(24, NULL, resp))<0){
        cout<<"SMTP info unknown"<<endl;
        goto done;
    }
    for(int i=0;i<strlen(resp); i++){
        if(*(resp+i) == ';')
            *(resp+i) = '\0';
    }
    cout<<"SMTP info: "<<resp<<endl;
    out = 1;
done:
    return out;
}

int stdSer::popTest(){
    int out = -1;
    char * ref=NULL;
    char resp[1024] = {0}, op[512]={0};
    if((out = getFromServer(110, NULL, resp))<0){
        cout<<"POP info unknown"<<endl;
        goto done;
    }
    ref=strtok(resp, " ");
    if(ref){
        ref = strtok(NULL, " ");
    }
    if(ref)
        cout<<"POP info: "<<ref<<endl;
    else {
        cout<<"POP info unknown"<<endl;
    }
    out = 1;
done:
    return out;
}

int stdSer::imapTest(){
    int out = -1;
    char * ref=NULL, *def = NULL, *cef = NULL, *eef = NULL;
    char resp[1024] = {0}, op[512]={0}, server[512]={0}, respCpy[1024]={0};
    if((out = getFromServer(143, NULL, resp))<0){
        cout<<"IMAP info unknown"<<endl;
        goto done;
    }
    strncpy(respCpy, resp, sizeof(resp));
    ref=strstr(resp, "CAPABILITY");
    if(ref){
        cef = strtok(ref+11, " ");
    }
    def =strstr(respCpy, "] ");
    if(def){
        eef = strtok(def+2, " ");
    }

    if(cef && eef)
        cout<<"IMAP info: Version "<<cef<<", Server "<<eef <<endl;
    else {
        cout<<"IMAP info unknown"<<endl;
    }
    out = 1;
done:
    return out;

}

int stdSer::scan(){
    httpTest();
    sshTest();
    whoisTest();
    smtpTest();
    popTest();
    imapTest();
}
