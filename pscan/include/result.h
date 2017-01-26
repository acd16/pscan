#include <iostream>
#include <map>
#include <string>
#include <vector>
#include <cstring>
#include <cstdio>
#include <sstream>

using namespace std;

class result{
    map<string, map<int, vector<string> > > *resultMap;
double duration;	
string getServiceName(int);
string service[1025];
void init();
    public:
        result(map<string, map<int, vector<string> > > *, double);
        int showResult();
};