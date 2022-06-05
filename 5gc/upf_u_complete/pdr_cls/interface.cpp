#include "interface.h"
#include "cls_core.h"
#include <iostream>

using namespace std;

#ifdef __cplusplus
extern "C"{
#endif

static MyClassifier *mycls = NULL;

void createCLS (char *filter_file, char *cls) {
    mycls = new MyClassifier();
    mycls->InitClass(filter_file, cls);
}

void interface(char *cls) {
    int a = mycls->doPdrSearch(cls);
    cout << "Lookup Result: " << a << "\t 0: match, -1: miss" <<endl;
}

#ifdef __cplusplus
}
#endif
