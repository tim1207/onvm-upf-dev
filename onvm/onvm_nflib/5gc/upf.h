#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
#include <rte_hash_crc.h>
#define DEFAULT_HASH_FUNC rte_hash_crc
#else
#include <rte_jhash.h>
#define DEFAULT_HASH_FUNC rte_jhash
#endif

typedef struct { int32_t seid; } UpfSession;

typedef struct {
  struct rte_hash* hash;
  char* data;
  int cnt;
  int entry_size;
} UpfSessionTable;

UpfSession* UpfSessionFindBySeid(uint64_t seid);
UpfSession* GetSessionByIndex(int32_t);

int PfcpSessionTableInit(void);
int PfcpSessionTableNFInit(void);
int UpfAddPfcpSessionBySeid(uint64_t seid);
void UpfPfcpSessionDeleteBySeid(uint64_t seid);
