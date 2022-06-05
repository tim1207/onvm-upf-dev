#include <iostream>
#include <stdlib.h>
#include "ElementaryClasses.h"
#include "IO/InputReader.h"
// #include "ClassBenchTraceGenerator/trace_tools.h"

#include "PartitionSort/PartitionSort.h"
#include "LinearList/LinearList.h"
#include "OVS/TupleSpaceSearch.h"
#include <stdio.h>

#include <assert.h>
#include <memory>
#include <chrono>
#include <string>
#include <sstream>

using namespace std;

class MyClassifier {
public:
    MyClassifier() {}
    ~MyClassifier() {}

    void InitClass (char *filter_file, char *cls);
    int doPdrSearch (char *cls);

    string filterFile;
    PartitionSort ps;
    PriorityTupleSpaceSearch ptss;
    LinearList ll;
};