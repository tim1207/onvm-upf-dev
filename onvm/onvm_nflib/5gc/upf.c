#include "upf.h"

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <rte_cycles.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memzone.h>

#define NO_FLAGS 0
#define MAX_NUM_OF_USERS 1024
#define MZ_PFCP_SESSION_TABLE_INFO "MProc_pfcp_session_table_info"

UpfSessionTable *upf_session_table = NULL;
UpfSessionTable **sdn_ft_p = NULL;

UpfSessionTable *upf_session_table_create(int cnt, int entry_size);

UpfSessionTable *upf_session_table_create(int cnt, int entry_size) {
  struct rte_hash *hash = NULL;
  struct rte_hash_parameters *hash_params;
  UpfSessionTable *ft;

  hash_params = (struct rte_hash_parameters *)rte_malloc(
      NULL, sizeof(struct rte_hash_parameters), 0);
  if (!hash_params) {
    return NULL;
  }

  char *name = rte_malloc(NULL, 64, 0);
  hash_params->entries = cnt;
  hash_params->key_len = sizeof(uint64_t);
  hash_params->hash_func = rte_jhash;
  hash_params->hash_func_init_val = 0;
  hash_params->name = name;
  hash_params->socket_id = rte_socket_id();

  snprintf(name, 64, "upf_session_%d-%" PRIu64, rte_lcore_id(),
           rte_get_tsc_cycles());

  if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
    hash = rte_hash_create(hash_params);
  }

  if (!hash) {
    return NULL;
  }
  ft = (UpfSessionTable *)rte_calloc("upf_session_table", 1,
                                     sizeof(UpfSessionTable), 0);
  if (!ft) {
    rte_hash_free(hash);
    return NULL;
  }

  ft->hash = hash;
  ft->cnt = cnt;
  ft->entry_size = entry_size;
  /* Create data array for storing values */
  ft->data = rte_calloc("upf_session_table_entry", cnt, entry_size, 0);
  if (!ft->data) {
    rte_hash_free(hash);
    rte_free(ft);
    return NULL;
  }
  return ft;
}

int PfcpSessionTableInit(void) {
  const struct rte_memzone *mz_ftp;

  upf_session_table =
      upf_session_table_create(MAX_NUM_OF_USERS, sizeof(UpfSession));

  if (upf_session_table == NULL) {
    rte_exit(EXIT_FAILURE, "Unable to create flow table\n");
  }
  mz_ftp =
      rte_memzone_reserve(MZ_PFCP_SESSION_TABLE_INFO, sizeof(UpfSessionTable *),
                          rte_socket_id(), NO_FLAGS);
  if (mz_ftp == NULL) {
    rte_exit(EXIT_FAILURE,
             "Cannot reserve memory zone for flow table pointer\n");
  }
  memset(mz_ftp->addr, 0, sizeof(UpfSessionTable *));
  sdn_ft_p = mz_ftp->addr;
  *sdn_ft_p = upf_session_table;

  return 0;
}

int PfcpSessionTableNFInit(void) {
  printf("%s called\n", __func__);
  const struct rte_memzone *mz_ftp;
  UpfSessionTable **ftp;

  mz_ftp = rte_memzone_lookup(MZ_PFCP_SESSION_TABLE_INFO);
  if (mz_ftp == NULL) rte_exit(EXIT_FAILURE, "Cannot get table pointer\n");
  ftp = mz_ftp->addr;
  upf_session_table = *ftp;

  if (upf_session_table == NULL) {
    printf("session table NULL\n");
  }
  if (upf_session_table != NULL && upf_session_table->hash == NULL) {
    printf("session hash table NULL\n");
  }
  printf("%s called\n", __func__);

  return 0;
}

int UpfAddPfcpSessionBySeid(uint64_t seid) {
  uint32_t cal_hash = rte_jhash(&seid, sizeof(uint64_t), 0);
  int32_t status = rte_hash_add_key_with_hash(upf_session_table->hash,
                                              (const void *)&seid, cal_hash);
  if (status < 0) {
    printf("Error adding key val\n");
  } else {
    printf("Added successfully %d \n", status);
  }
  return status;
}

void UpfPfcpSessionDeleteBySeid(uint64_t seid) {
  uint32_t cal_hash = rte_jhash(&seid, sizeof(uint64_t), 0);
  int32_t status = rte_hash_del_key_with_hash(upf_session_table->hash,
                                              (const void *)&seid, cal_hash);
  if (status < 0) {
    printf("Error adding key val\n");
  } else {
    printf("Delete successfully %d \n", status);
  }
}

UpfSession *GetSessionByIndex(int32_t idx) {
  return (UpfSession *)&upf_session_table
      ->data[idx * upf_session_table->entry_size];
}

UpfSession *UpfSessionFindBySeid(uint64_t seid) {
  uint32_t cal_hash = rte_jhash(&seid, sizeof(uint64_t), 0);
  int32_t status = rte_hash_lookup_with_hash(upf_session_table->hash,
                                             (const void *)&seid, cal_hash);
  if (status < 0) {
    return NULL;
  }
  return GetSessionByIndex(status);
}
