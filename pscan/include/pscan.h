#include <iostream>
#include <map>
#include <vector>
#include <string>
#include <queue>
#include <time.h>
#include <sys/time.h>
#include <cstdio>
#include "setup.h"
#include "synScan.h"
#include "tcpScan.h"
#include "ackScan.h"
#include "udpScan.h"
#include "result.h"
#include "stdSer.h"
#include <pthread.h>

#define SYN_SCAN 0
#define FIN_SCAN 1
#define NULL_SCAN 2
#define XMAS_SCAN 3
#define ACK_SCAN 4
#define UDP_SCAN 5

int getTCPFlag(string scan_type);
void computeScan(string , int , string , map<string, map<int, vector<string> > > *);
u_int32_t getLocalAddr();
void pushToQueue(string , int , string , map<string, map<int, vector<string> > > *);
void disPatchJobs(int);
void *threadedScanRun(void *);

typedef struct job{
    string dstIp;
    int dstPort;
    string scan_type;
    map<string, map<int, vector<string> > >* res;
}scanJob;

typedef struct threadInfo{
    scanJob curjob;
    int numThreads;
}tInfo;

queue <scanJob> jobQueue;
int speedup = 0;
int numScanDone = 0, numScanPerThread;
pthread_mutex_t spMutex, waitMutex;
pthread_cond_t cood, waitForNext;
