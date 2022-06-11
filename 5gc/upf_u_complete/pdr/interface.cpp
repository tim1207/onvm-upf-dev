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
    if (a >= 0) {
        // cout << "PDR Match" <<endl;
    } else if (a == -1) {
        cout << "PDR Miss" <<endl;
    } else {
        cout << "PDR Lookup abort(): " << a <<endl;
    }
}

#ifdef __cplusplus
}
#endif
