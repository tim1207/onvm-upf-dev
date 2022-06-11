#include <cstring>
#include "cls_core.h"

using namespace std;

void MyClassifier::InitClass(char *filter_file, char *cls) {
    string filterFile(filter_file);
    vector<Rule> rules = InputReader::ReadFilterFile(filterFile);

    if (strcmp(cls, "ps") == 0) {
        ps.ConstructClassifier(rules);
        printf("PartitionSort classifier is constructed\n");
    } else if (strcmp(cls, "ptss") == 0) {
        ptss.ConstructClassifier(rules);
        printf("PriorityTupleSpaceSearch classifier is constructed\n");
    } else if (strcmp(cls, "ll") == 0) {
        ll.ConstructClassifier(rules);
        printf("LinearList classifier is constructed\n");
    } else if (strcmp(cls, "tss") == 0) {
        tss.ConstructClassifier(rules);
        printf("TupleSpaceSearch classifier is constructed\n");
    } else {
        printf("Unknown classifier: %s\n", cls);
        abort();
    }

}

int MyClassifier::doPdrSearch(char *cls) {
    //210942984:210942991 210942944:210942959 53:53 22:22 17:17 17:17 17:17 0:0 0:0 0:0 0:0 0:0 0:0 0:0 0:0 0:0 0:0 0:0 0:0 0:0 0:0 0:0
    Packet p = {210942984, 210942944, 53, 22, 17, 17, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    if (strcmp(cls, "ps") == 0) {
        return ps.ClassifyAPacket(p);
    } else if (strcmp(cls, "ptss") == 0) {
        return ptss.ClassifyAPacket(p);
    } else if (strcmp(cls, "ll") == 0) {
        return ll.ClassifyAPacket(p);
    } else if (strcmp(cls, "tss") == 0) {
        return tss.ClassifyAPacket(p);
    } else {
        printf("Unknown classifier: %s\n", cls);
        abort();
    }
    return -1;
}
