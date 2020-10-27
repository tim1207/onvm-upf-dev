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

#define MAX_PDR_RULE 16
#define MAX_FAR_RULE 8

/* Forward Action Rules - Forwarding Parameters */
typedef struct
{
  uint16_t flags;
#define FAR_F_REDIRECT_INFORMATION	BIT(0)
#define FAR_F_OUTER_HEADER_CREATION	BIT(1)

#if 0
  pfcp_destination_interface_t dst_intf;
  u32 dst_sw_if_index;
  u32 nwi_index;

  pfcp_redirect_information_t redirect_information;
  pfcp_outer_header_creation_t outer_header_creation;

  u32 peer_idx;
  u8 *rewrite;
#endif
} upf_far_forward_t;

/* Forward Action Rules */
typedef struct
{
  uint16_t id;
  uint16_t apply_action;
#define FAR_DROP       0x0001
#define FAR_FORWARD    0x0002
#define FAR_BUFFER     0x0004
#define FAR_NOTIFY_CP  0x0008
#define FAR_DUPLICATE  0x0010

  union
  {
    upf_far_forward_t forward;
    uint16_t bar_id;
  };
} upf_far_t;

#define OUTER_HEADER_REMOVAL_GTP_IP4   0
#define OUTER_HEADER_REMOVAL_GTP_IP6   1
#define OUTER_HEADER_REMOVAL_UDP_IP4   2
#define OUTER_HEADER_REMOVAL_UDP_IP6   3
#define OUTER_HEADER_REMOVAL_IP4       4
#define OUTER_HEADER_REMOVAL_IP6       5
#define OUTER_HEADER_REMOVAL_GTP       6
#define OUTER_HEADER_REMOVAL_S_TAG     7
#define OUTER_HEADER_REMOVAL_S_C_TAG   8
/* Packet Detection Rules */
typedef struct
{
  uint32_t id;
  uint16_t precedence;
#if 0
  upf_pdi_t pdi;
#endif
  uint8_t outer_header_removal;

  uint16_t far_id;
  upf_far_t *far;
  uint16_t *urr_ids;
  uint32_t *qer_ids;
  uint8_t active;
} upf_pdr_t;

typedef struct { 
  int32_t seid;
  uint64_t smfSeid;
  uint64_t upfSeid;
  upf_pdr_t pdr_list[MAX_PDR_RULE];
  upf_far_t far_list[MAX_FAR_RULE];
} UpfSession;

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
