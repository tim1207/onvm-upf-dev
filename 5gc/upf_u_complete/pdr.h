#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "upf_context.h"

// Define the key for the uplink hash table (TEID)
typedef struct {
    uint32_t teid;
} TeidKey;

// Define the key for the downlink hash table (two IPs)
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
} IpPair;

// Define a hash table node
typedef struct Node {
    void* key;
    UpfPDR* pdr; // Declare UpfPDR pointer directly in Node
    struct Node* next;
} Node;

// Define the hash table
typedef struct {
    Node** buckets;
    int size;
    unsigned int (*hashFunction)(void*, int);
} HashMap;

// Hash function (TEID)
unsigned int teidHash(void* key, int tableSize) {
    TeidKey* teidKey = (TeidKey*)key;
    return teidKey->teid % tableSize;
}

// Hash function (IP Pair)
unsigned int ipPairHash(void* key, int tableSize) {
    IpPair* ipPair = (IpPair*)key;
    uint32_t hash = 5381;

    hash = ((hash << 5) + hash) + (ipPair->src_ip & 0xFF);
    hash = ((hash << 5) + hash) + ((ipPair->src_ip >> 8) & 0xFF);
    hash = ((hash << 5) + hash) + ((ipPair->src_ip >> 16) & 0xFF);
    hash = ((hash << 5) + hash) + ((ipPair->src_ip >> 24) & 0xFF);

    hash = ((hash << 5) + hash) + (ipPair->dst_ip & 0xFF);
    hash = ((hash << 5) + hash) + ((ipPair->dst_ip >> 8) & 0xFF);
    hash = ((hash << 5) + hash) + ((ipPair->dst_ip >> 16) & 0xFF);
    hash = ((hash << 5) + hash) + ((ipPair->dst_ip >> 24) & 0xFF);

    return hash % tableSize;
}

// Initialize the hash table
HashMap* createHashMap(int size, unsigned int (*hashFunction)(void*, int)) {
    HashMap* map = (HashMap*)malloc(sizeof(HashMap));
    map->size = size;
    map->buckets = (Node**)calloc(size, sizeof(Node*));
    map->hashFunction = hashFunction;
    return map;
}

// Insert data
void insert(HashMap* map, void* key, UpfPDR* pdr) {
    unsigned int index = map->hashFunction(key, map->size);
    Node* newNode = (Node*)malloc(sizeof(Node));
    newNode->key = key;
    newNode->pdr = pdr;
    newNode->next = map->buckets[index];
    map->buckets[index] = newNode;
}

// Find data
Node* find(HashMap* map, void* key, int keyType) {
    unsigned int index = map->hashFunction(key, map->size);
    Node* current = map->buckets[index];
    if (keyType == 0) {
        TeidKey* searchKey = (TeidKey*)key;
        while (current != NULL) {
            TeidKey* currentKey = (TeidKey*)current->key;
            if (currentKey->teid == searchKey->teid) {
                return current;
            }
            current = current->next;
        }
    } else {
        IpPair* searchKey = (IpPair*)key;
        while (current != NULL) {
            IpPair* currentKey = (IpPair*)current->key;
            if (currentKey->src_ip == searchKey->src_ip && currentKey->dst_ip == searchKey->dst_ip) {
                return current;
            }
            current = current->next;
        }
    }
    return NULL;
}

// Free the hash table
void freeHashMap(HashMap* map) {
    if (map == NULL) {
        return;
    }
    for (int i = 0; i < map->size; i++) {
        Node* current = map->buckets[i];
        while (current != NULL) {
            Node* temp = current;
            current = current->next;
            free(temp->key); // Free the memory of the key
            free(temp);
        }
    }
    free(map->buckets);
    free(map);
}

// Print the hash table
void printHashMap(HashMap* map, int keyType) {
    printf("Hash Table:\n");
    if (map == NULL) {
        return;
    }
    for (int i = 0; i < map->size; i++) {
        Node* current = map->buckets[i];
        printf("Bucket %d: ", i);
        while (current != NULL) {
            if (keyType == 0) {
                TeidKey* teidKey = (TeidKey*)current->key;
                printf("(TEID: %u, PDR is %s) -> ", teidKey->teid, current->pdr ? "not null" : "null");
            } else {
                IpPair* ipPairKey = (IpPair*)current->key;
                printf("(src_ip: %u, dst_ip: %u, PDR is %s) -> ", ipPairKey->src_ip, ipPairKey->dst_ip, current->pdr ? "not null" : "null");
            }
            current = current->next;
        }
        printf("NULL\n");
    }
}

void initializePdrHashTables(HashMap** uplinkMap, HashMap** downlinkMap) {
    *uplinkMap = createHashMap(1009, teidHash);
    *downlinkMap = createHashMap(1009, ipPairHash);
}
