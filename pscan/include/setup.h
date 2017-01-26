#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <getopt.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

using namespace std;

class Setup{
    int parseArgs();
    int argc;
    char ** argv;
    string fileName;
    string prefix;
	string ports;
	string scan;
	int numThread;
	string ipAddress;
    vector<string> ipList;
	vector<int> portList;
	vector<string> scanList;

    int getFromFile();
	int getFromSingleIP();
    int prefixParse();
	void parsePorts();
	void parseScans();
    public:
        int parseIps();
        void printIps();
        vector<string> getIPs();
		vector<int> getPorts();
		vector<string> getScans();
        int getNumThreads();
        int init(int& _argc, char ** _argv);
};
