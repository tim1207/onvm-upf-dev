#ifndef __N4_ONVM_PFCP_PATH_H__
#define __N4_ONVM_PFCP_PATH_H__

#include <rte_mbuf.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"

int packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta, struct onvm_nf_local_ctx *nf_local_ctx);

#endif /* __N4_PFCP_PATH_H__ */
