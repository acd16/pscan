#include "include/setup.h"

using namespace std;

int usage(FILE *pFp)
{
    fprintf(pFp, "portScanner [OPTIONS] \n"
            "--help \t\t Print this help screen and exit\n"
			"--ports \t Ports to scan\n"
			"--ip \t\t IP address to scan\n"
            "--prefix \t IP prefix to scan\n"
			"--file \t\t File with list of IP addresses to scan\n"
			"--speedup \t How many parallel threads to use\n"
			"--scan \t\t Scan flags\n");
}

int Setup::parseArgs(){
    int ch, index=0;
    static struct option long_options[]={
        {"help", no_argument, 0, 'h'},
		{"ports", required_argument, 0, 'p'},
		{"ip", required_argument, 0, 'i'},
        {"file", required_argument, 0, 'f'},
        {"prefix", required_argument, 0, 'r'},
		{"speedup", required_argument, 0, 't'},
		{"scan", required_argument, 0, 's'},
        {0,0,0,0}
    };
    while((ch = getopt_long(argc, argv, "hp:f:r:i:t:s:", long_options,&index))){
        if(ch==-1)
            break;
        switch(ch){
            cout<<"args is "<<ch;
            case 'h':
                usage(stdout);
                exit(0);
                break;
            case 'f':
                fileName = optarg;
                break;
			case 'p':
                ports = optarg;
				parsePorts();
                break;
            case 'r':
                prefix = optarg;
                break;
			case 'i':
                ipAddress = optarg;
                break;
			case 's':
                scan = optarg;
				parseScans();
                break;
			case 't':
                numThread = atoi(optarg);
                break;
            default:
                fprintf(stderr,"ERROR: Unknown option '-%c'\n",ch);
                usage(stdout);
                exit(1);
        }
    }
}

void Setup::parsePorts(){
	int portStart, portEnd;
	char portArg[50];
	strcpy(portArg, ports.c_str());
	const char sep[] = ",";
	char *token;

	token = strtok(portArg, sep);
	while (token){
		if (strstr(token, "-") != NULL){
			sscanf(token, "%d-%d", &portStart, &portEnd);
		}
		else{
			sscanf(token, "%d", &portStart);
			portEnd = portStart;
		}
		for (int i = portStart; i <= portEnd; ++i)
			portList.push_back(i);
		token = strtok(NULL, sep);
	}
}

void Setup::parseScans(){
	char scanArg[50];
	strcpy(scanArg, scan.c_str());
	const char sep[] = " ";
	char *token;

	token = strtok(scanArg, sep);
	while (token){
		scanList.push_back(token);
		token = strtok(NULL, sep);
	}
}

int Setup::getFromFile(){
    int out=0;
    struct sockaddr_in ip;
	string line;

    if(!fileName.empty()){

        ifstream ipFile (fileName.c_str());
        if(ipFile.is_open()){
            while (getline(ipFile, line)){
                if(inet_pton(AF_INET, line.c_str(), &(ip.sin_addr)) == 1){
                    //cout<<"pushing "<<line<<endl;
                    ipList.push_back(line);
                }
                else{
					cout << "Invalid IP adress: " << line << endl;
                    out = -1;
                    goto out;
                }
            }
        }
        else {
            cout<<"Error opening file"<<endl;
            out = -1;
        }
    }
out:
    return out;
}

int Setup::getFromSingleIP(){
    int out=0;
    struct sockaddr_in ip;

	if(inet_pton(AF_INET, ipAddress.c_str(), &(ip.sin_addr)) == 1){
		ipList.push_back(ipAddress);
	}
	else{
		cout << "Invalid IP adress: " << ipAddress << endl;
		out = -1;
		goto out;
	}

out:
    return out;
}

int Setup::prefixParse(){
    int out=-1, prefixLen=0;
    char ip[20] = {};
    char delim[2] = "/";
    struct sockaddr_in ipAddr, subnet;
    char subnetAddr[INET_ADDRSTRLEN] = {0};
    char * add = NULL, *len = NULL;
    strncpy(ip, prefix.c_str(), sizeof(ip));
    add = strtok(ip, delim);
    len = strtok(NULL, delim);
    if(add == NULL || len == NULL)
        goto out;
    prefixLen = atoi(len);
    if(prefixLen > 32 || prefixLen < 0){
        cout << "Invalid prefix length"<<endl;
        goto out;
    }
    if((inet_pton(AF_INET, add, &(ipAddr.sin_addr))!=1)){
        cout << "Invalid ip subnet"<<endl;
        goto out;
    }
    /* get the actual subnet as the given prefix could be and address in the
     * subnet as well */
    subnet.sin_addr.s_addr =  ntohl(htonl(ipAddr.sin_addr.s_addr) & ~(((uint32_t)1<<(32-prefixLen)) - 1));
    inet_ntop(AF_INET, &(subnet.sin_addr.s_addr), subnetAddr, INET_ADDRSTRLEN);
    for(int i=0; i<(1<<(32-prefixLen)); i++){
        inet_ntop(AF_INET, &(subnet.sin_addr.s_addr), subnetAddr, INET_ADDRSTRLEN);
        ipList.push_back(subnetAddr);
        subnet.sin_addr.s_addr = ntohl(htonl(subnet.sin_addr.s_addr)+1);
    }
    out=0;
out:
    return out;
}

int Setup::parseIps(){
    int out = 0;
    parseArgs();
	if(!ipAddress.empty() && (out=getFromSingleIP()))
        goto out;
    if(!fileName.empty() && (out=getFromFile()))
        goto out;
    if(!prefix.empty() && (out=prefixParse()))
        goto out;
out:
    return out;
}

vector<string> Setup::getIPs(){
    return ipList;
}

vector<int> Setup::getPorts(){
    return portList;
}

vector<string> Setup::getScans(){
    return scanList;
}

int Setup::getNumThreads(){
    return numThread;
}

void Setup::printIps(){
    for(vector<string>::const_iterator it=ipList.begin();it != ipList.end(); it++)
        cout<<*it<<endl;
}

int Setup::init(int& _argc, char ** _argv){
    argc = _argc;
    argv = _argv;
    numThread = 0;
}
