#include "include/pscan.h"
#include "include/glob.h"
using namespace std;

int main(int argc, char **argv){
    Setup setup;

    map<string, map<int, vector<string> > > resultMap;

    vector<string> ipList;
    vector<int> portList;
    vector<string> scanList;

    string ip, scan_type;
    int port, threads=0, out =0;

    setup.init(argc, argv);
    if(setup.parseIps()){
        cout<<"Error parsing ips"<<endl;
        exit(1);
    }

    ipList = setup.getIPs();
    portList = setup.getPorts();
    scanList = setup.getScans();
    threads = setup.getNumThreads();

    numScanPerThread = portList.size() * scanList.size();

    struct timeval start, end;
    double duration;
    gettimeofday(&start, NULL);

    pthread_mutex_init(&waitMutex, NULL);
    pthread_cond_init(&waitForNext, NULL);

    for(vector<string>::const_iterator it_ip = ipList.begin(); it_ip != ipList.end(); it_ip++){

	if(threads > 1){
	  pthread_mutex_init(&waitMutex, NULL);
	  pthread_cond_init(&waitForNext, NULL);
	}

	ip = *it_ip;
	cout<<"in loop for "<<ip<<endl;
	pthread_t tid;
	if((out =startPcapThread(tid, ip)) < 0){
	    cout<<"err in pcap thread"<<endl;
	    continue;
	}
	for(vector<int>::const_iterator it_port = portList.begin(); it_port != portList.end(); it_port++){

		port = *it_port;

		for(vector<string>::const_iterator it_scan = scanList.begin(); it_scan != scanList.end(); it_scan++){

			scan_type = *it_scan;

			cout << "Doing operation on [" << ip << ":" << port << "][" << scan_type << "]" << endl;
			if(threads > 1){
			    //cout<<"THREADS "<<threads<<endl;
			    pushToQueue(ip, port, scan_type, &resultMap);
			}
			else{
			    numScanDone = -999999;
			    computeScan(ip, port, scan_type, &resultMap);
			    cout<<"done with scan"<<endl;
			}
		}
	}

	if(threads > 1){
	    numScanDone = 0;
	    disPatchJobs(threads);

	    pthread_mutex_lock(&waitMutex);
	    pthread_cond_wait(&waitForNext, &waitMutex);
	    pthread_mutex_unlock(&waitMutex);

	    cout<<"break loop"<<endl;
	    sleep(1);
	    if(pktHandle){
		pcap_breakloop(pktHandle);
		pcap_close(pktHandle);
		pktHandle = NULL;
	    }
	    //pthread_cancel(tid);
	    freeList();
	    sleep(1);
	    pthread_mutex_destroy(&waitMutex);
	    pthread_cond_destroy(&waitForNext);
	}
	else{
	  cout<<"break loop"<<endl;
	  if(pktHandle){
	      pcap_breakloop(pktHandle);
	      pcap_close(pktHandle);
	      pktHandle = NULL;
	  }
	  //pthread_cancel(tid);
	  freeList();
	}
    stdSer stdser(ip);
    stdser.scan();
    }

    gettimeofday(&end, NULL);
    duration = (double) ((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec)) / 1000000.0;

    /*
string gg="129.79.247.87";
int p = 22;
    */

    result res(&resultMap, duration);
    res.showResult();
}

void disPatchJobs(int numThreads){
    pthread_t  threads[10];
    scanJob curJob;
    tInfo *curThreadInfo;
    cout << "in disPatchJobs "<< numThreads<<endl;
    //threads = (pthread_t *)malloc(sizeof(pthread_t) * numThreads);
    pthread_mutex_init(&spMutex, NULL);
    pthread_cond_init (&cood, NULL);
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    while(!jobQueue.empty()){
        cout<<"Q not empty"<<endl;
        curJob = jobQueue.front();
	curThreadInfo = new tInfo();
        curThreadInfo->curjob = curJob;
        curThreadInfo->numThreads = numThreads;
        jobQueue.pop();
        cout<<"Thread with "<<curThreadInfo->curjob.dstIp<<" "<< curThreadInfo->curjob.dstPort<<endl;
        pthread_mutex_lock(&spMutex);
        if(speedup>numThreads){
            cout<<"waiting for speedup"<<endl;
            pthread_cond_wait(&cood, &spMutex);
        }
        //cout<<"spawning thread for "<<endl;
        pthread_create(&threads[speedup], &attr, threadedScanRun, (void *)curThreadInfo);
        //cout<<"INC speedup "<<speedup<<endl;
        speedup++;
        pthread_mutex_unlock(&spMutex);
    }
    pthread_mutex_destroy(&spMutex);
    pthread_cond_destroy(&cood);
}

void pushToQueue(string ip, int port, string scan_type, map<string,
        map<int, vector< string> > > *resultMap){
    scanJob * curJob = new scanJob();
    curJob->dstIp = ip;
    curJob->dstPort = port;
    curJob->scan_type = scan_type;
    curJob->res = resultMap;
    jobQueue.push(*curJob);
    delete(curJob);
}

void *threadedScanRun(void *val){
    tInfo * curThread;
    curThread = (tInfo*)val;
    cout<<"calling scan"<<endl;
    cout<<"["<<(curThread->curjob).dstIp<<curThread->curjob.dstPort<<curThread->curjob.scan_type<<"]"<<endl;
    computeScan(curThread->curjob.dstIp, curThread->curjob.dstPort,
            curThread->curjob.scan_type, curThread->curjob.res);
    //computeScan("gg", 10,"SYN", NULL);
    pthread_mutex_lock(&spMutex);
    speedup--;
    //cout<<"DEC speedup "<<speedup<<endl;
    pthread_cond_signal(&cood);
    pthread_mutex_unlock(&spMutex);
    //delete(curThread);
}

void computeScan(string ip, int port, string scan_type, map<string, map<int, vector< string> > > *resultMap){
    cout<<"IN compute scan "<<endl;
    uint32_t srcIp = getLocalAddr();
	if (scan_type == "SYN"){
		startSynScan(ip, port, resultMap, srcIp);
	}
	else if (scan_type == "ACK"){
		startAckScan(ip, port, resultMap, srcIp);
	}
	else if (scan_type == "FIN" || scan_type == "NULL" || scan_type == "XMAS"){
		startTcpScan(ip, port, getTCPFlag(scan_type), resultMap, srcIp);
	}
	else if (scan_type == "UDP"){
		udpScan myscan(ip, port, resultMap, srcIp);
		myscan.scan();
	}
	else{
		cout << "ERROR: Unknown scan type " << scan_type<< endl;
	}
	numScanDone++;
	if (numScanDone == numScanPerThread){
	    pthread_cond_signal(&waitForNext);
	}
}

int getTCPFlag(string scan_type){
	int flag = 0;
	if (scan_type == "FIN")
		flag |= 1<<0;
	else if (scan_type == "NULL")
		flag |= 0;
	else if (scan_type == "XMAS"){
		flag |= 1<<0;	// FIN
		flag |= 1<<3;	// PSH
		flag |= 1<<5;	// URG
	}
	return flag;
}

u_int32_t getLocalAddr(){
    /*struct sockaddr_in *sa;
    struct addrinfo hints, *p, *s;
    char ipstr[32];
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    getaddrinfo("localhost", NULL, &hints, &p);
    //for(s = p;p!=NULL; p =p->ai_next){
    sa = (struct sockaddr_in *)p->ai_addr;
        inet_ntop(AF_INET, sa, ipstr, sizeof(ipstr));
    //}
    cout<<"SRC ADDR "<<ipstr<<endl;
    return (u_int32_t)sa->sin_addr.s_addr;*/
    int out=0;
    char str[INET_ADDRSTRLEN] = {0};
    char dummyIp[INET_ADDRSTRLEN] = "8.8.8.8";
    struct ifaddrs *ifaddr, *inf;
    struct sockaddr_in da = {0}, sa = {0};
    inet_pton(AF_INET, dummyIp, &da.sin_addr);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    da.sin_family = AF_INET;
    da.sin_addr.s_addr = inet_addr(dummyIp);
    da.sin_port = htons(53);
    if(sock){
            out = connect(sock, (struct sockaddr*)&da, sizeof(da));
        if(!out){
            socklen_t addLen = sizeof(sa);
            out = getsockname(sock, (struct sockaddr*)&sa, &addLen);
            inet_ntop(AF_INET, &sa.sin_addr.s_addr, str, sizeof(str));
            cout<<"ADDR "<<str<<" for "<<dummyIp<<endl;
            if(!out){
                return sa.sin_addr.s_addr;
            }
        }
    }
    /*if(getifaddrs(&ifaddr)){
        cout<<"Error getting local ip"<<endl;
        exit(1);
    }
    inf = ifaddr;
    while(inf){
        if(inf->ifa_addr == NULL)
            continue;
        if(!strcmp(inf->ifa_name, "eth0") &&
                (inf->ifa_addr->sa_family == AF_INET)){
            sa = (struct sockaddr_in *)inf->ifa_addr;
            srcAddr = sa->sin_addr.s_addr;
            inet_ntop(AF_INET, &(sa->sin_addr.s_addr), str, INET_ADDRSTRLEN);
            break;
        }
        inf = inf->ifa_next;
    }
    cout<<"SRC addr "<<str<<endl;
    freeifaddrs(ifaddr);*/
    return -1;
}
