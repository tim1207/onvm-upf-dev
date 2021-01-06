/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2019 George Washington University
 *            2015-2019 University of California Riverside
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * The name of the author may not be used to endorse or promote
 *       products derived from this software without specific prior
 *       written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 ********************************************************************/

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <rte_common.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <unistd.h>

#include "5gc/gtp.h"
#include "5gc/upf.h"
#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"

#define NF_TAG "upf_u"

#undef SELF_IP
#define SELF_IP 2989009088
#define PKT_READ_SIZE ((uint16_t)32)

/* For advanced rings scaling */
rte_atomic16_t signal_exit_flag;
struct child_spawn_info {
  struct onvm_nf_init_cfg *child_cfg;
  struct onvm_nf *parent;
};

uint32_t buffer_length = 0;

void sig_handler(int sig);

void sig_handler(int sig) {
  if (sig != SIGINT && sig != SIGTERM) return;

  /* Will stop the processing for all spawned threads in advanced rings mode */
  rte_atomic16_set(&signal_exit_flag, 1);
}

upf_pdr_t *GetPdrByUeIpAddress(struct rte_mbuf *pkt, uint32_t addr) {
  return NULL;
}

upf_pdr_t *GetPdrByTeid(struct rte_mbuf *pkt, uint32_t td) {
  UpfSession *session = UpfSessionFindBySeid(td);
  if (!session) {
    return NULL;
  }
  int i = 0;
  for (i = 0; i < MAX_PDR_RULE; i++) {
    if (session->pdr_list[i].active == 1) {
      return &session->pdr_list[i];
    }
  }
  return NULL;
}

upf_far_t *GetFarById(uint16_t id) { return NULL; }


static int packet_handler(
    __attribute__((unused)) struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
    __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
  meta->action = ONVM_NF_ACTION_DROP;

  struct rte_ipv4_hdr *iph = onvm_pkt_ipv4_hdr(pkt);
  struct rte_udp_hdr *udp_header = onvm_pkt_udp_hdr(pkt);

  if (!iph) {
    iph = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, 16);
  }

  if (!iph) {
    return 0;
  }

  upf_pdr_t *pdr;

  // Step 1: Identify if it is a uplink packet or downlink packet
  if (iph->dst_addr != SELF_IP) {  //
    // invariant(dst_port == GTPV1_PORT);
    // Step 2: Get PDR rule
    pdr = GetPdrByUeIpAddress(pkt, iph->dst_addr);
  } else {
    // extract TEID from
    // Step 2: Get PDR rule
    uint32_t teid = get_teid_gtp_packet(pkt, udp_header, meta);
    pdr = GetPdrByTeid(pkt, teid);
  }

  if (!pdr) {
    printf("no PDR found for %pI4, skip\n", &iph->dst_addr);
    // TODO(vivek): what to do?
    return 0;
  }

  upf_far_t *far;
  far = pdr->far;

  if (!far) {
    printf("There is no FAR related to PDR[%u]\n", pdr->id);
    meta->action = ONVM_NF_ACTION_DROP;
    return 0;
  }

  // TODO(vivek): implement the removal policy
  switch (pdr->outer_header_removal) {
    case OUTER_HEADER_REMOVAL_GTP_IP4: {
      int outer_hdr_len = sizeof(struct rte_ether_hdr) +
                                sizeof(struct rte_ipv4_hdr) +
                                sizeof(struct rte_udp_hdr) + sizeof(gtpv1_t);
      outer_hdr_len = 54;
      rte_pktmbuf_adj(pkt, (uint16_t)outer_hdr_len);

      // Prepend ethernet header
      struct rte_ether_hdr *eth_hdr =
          (struct rte_ether_hdr *)rte_pktmbuf_prepend(
              pkt, (uint16_t)sizeof(struct rte_ether_hdr));

      eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
      int j = 0;
      for (j = 0; j < RTE_ETHER_ADDR_LEN; ++j) {
        eth_hdr->d_addr.addr_bytes[j] = j;
      }
    } break;
    case OUTER_HEADER_REMOVAL_GTP_IP6:
    case OUTER_HEADER_REMOVAL_UDP_IP4:
    case OUTER_HEADER_REMOVAL_UDP_IP6:
    case OUTER_HEADER_REMOVAL_IP4:
    case OUTER_HEADER_REMOVAL_IP6:
    case OUTER_HEADER_REMOVAL_GTP:
    case OUTER_HEADER_REMOVAL_S_TAG:
    case OUTER_HEADER_REMOVAL_S_C_TAG:
    default:
      printf("unknown\n");
  }

  if (far) {
    switch (far->apply_action) {
      case FAR_DROP:
        printf("Dropping the packet based on PDR\n");
        break;
      case FAR_FORWARD:
	meta->action = ONVM_NF_ACTION_OUT;
	meta->destination = pkt->port^1;
        // TODO(vivek): Implement forward policy
        break;
      case FAR_BUFFER:
        if (far->curr_cap < MAX_BUFFER_LENGTH) {
          far->curr_cap++;
          printf("Buffering the packet, total packet in the buffer: %d\n", far->curr_cap);
        } else {
          printf("Dropping packet due to buffer full: %d\n", far->curr_cap);
        }
        break;
      // TODO(vivek): Implement buffering policy
      case FAR_NOTIFY_CP:
      // TODO(vivek): Implement notify CP policy
      case FAR_DUPLICATE:
      // TODO(vivek): Implement duplicate policy
      default:
        printf("Unspec apply action[%u] in FAR[%u] and related to PDR[%u]",
               far->apply_action, far->id, pdr->id);
    }
  }

  return 0;
}

static int
thread_main_loop(struct onvm_nf_local_ctx *nf_local_ctx) {
        void *pkts[PKT_READ_SIZE];
        struct onvm_pkt_meta *meta;
        uint16_t i, nb_pkts;
        struct rte_mbuf *pktsTX[PKT_READ_SIZE];
        int tx_batch_size;
        struct rte_ring *rx_ring;
        struct rte_ring *msg_q;
        struct onvm_nf *nf;
        struct onvm_nf_msg *msg;
        struct rte_mempool *nf_msg_pool;

        nf = nf_local_ctx->nf;

        onvm_nflib_nf_ready(nf);

        /* Get rings from nflib */
        rx_ring = nf->rx_q;
        msg_q = nf->msg_q;
        nf_msg_pool = rte_mempool_lookup(_NF_MSG_POOL_NAME);

        printf("Process %d handling packets using advanced rings\n", nf->instance_id);
        if (onvm_threading_core_affinitize(nf->thread_info.core) < 0)
                rte_exit(EXIT_FAILURE, "Failed to affinitize to core %d\n", nf->thread_info.core);

        uint16_t chalne_do = 1;
        int error_code = 0;
        while (!rte_atomic16_read(&signal_exit_flag)) {
                /* Check for a stop message from the manager */
                if (unlikely(rte_ring_count(msg_q) > 0)) {
                        msg = NULL;
                        rte_ring_dequeue(msg_q, (void **)(&msg));
                        if (msg->msg_type == MSG_STOP) {
                                rte_atomic16_set(&signal_exit_flag, 1);
                        } else if (msg->msg_type == MSG_FROM_NF) {
                          printf("Received message from NF\n");
                          struct FlushBufferMessage * message;
                          message = (struct FlushBufferMessage *) msg->msg_data;
                          if (message != NULL) {
                            if (message->far != NULL && message->far->apply_action == FAR_BUFFER) {
                              printf("%s the %u packets from buffer based on the new action\n", message->new_action == FAR_DROP? "FAR_DROP" : "FAR_FORWARD", message->far->curr_cap);
                              message->far->curr_cap = 0;
                              message->far->apply_action = message->new_action;
                            } else {
                              printf("Current action is not buffering any packet, something went wrong\n");
                            }
                          }
                        } else {
                                printf("Received message %d, ignoring", msg->msg_type);
                        }
                        rte_mempool_put(nf_msg_pool, (void *)msg);
                }

                tx_batch_size = 0;
                nb_pkts = rte_ring_dequeue_burst(rx_ring, pkts, PKT_READ_SIZE, NULL);

                /* Process all the dequeued packets */
                for (i = 0; i < nb_pkts; i++) {
                        meta = onvm_get_pkt_meta((struct rte_mbuf *)pkts[i]);
                        packet_handler((struct rte_mbuf *)pkts[i], meta, nf_local_ctx);
                        pktsTX[tx_batch_size++] = pkts[i];
                }

                onvm_pkt_process_tx_batch(nf->nf_tx_mgr, pktsTX, tx_batch_size, nf);
                if (tx_batch_size < PACKET_READ_SIZE) {
                        onvm_pkt_flush_all_nfs(nf->nf_tx_mgr, nf);
                }
        }
        return 0;
}
int main(int argc, char *argv[]) {
  int arg_offset;
  struct onvm_nf_local_ctx *nf_local_ctx;
  struct onvm_nf_function_table *nf_function_table;

  nf_local_ctx = onvm_nflib_init_nf_local_ctx();
#ifdef BUFFER_MODE
  printf("Using advanced mode\n");
  /* If we're using advanced rings also pass a custom cleanup function,
   * this can be used to handle NF specific (non onvm) cleanup logic */
  rte_atomic16_init(&signal_exit_flag);
  rte_atomic16_set(&signal_exit_flag, 0);
  onvm_nflib_start_signal_handler(nf_local_ctx, sig_handler);

  /* No need to define a function table as adv rings won't run onvm_nflib_run */
  nf_function_table = NULL;
#else
  onvm_nflib_start_signal_handler(nf_local_ctx, NULL);
  nf_function_table = onvm_nflib_init_nf_function_table();
  nf_function_table->pkt_handler = &packet_handler;
#endif

  if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG, nf_local_ctx,
                                    nf_function_table)) < 0) {
    onvm_nflib_stop(nf_local_ctx);
    if (arg_offset == ONVM_SIGNAL_TERMINATION) {
      printf("Exiting due to user termination\n");
      return 0;
    } else {
      rte_exit(EXIT_FAILURE, "Failed ONVM init\n");
    }
  }

  argc -= arg_offset;
  argv += arg_offset;

  PfcpSessionTableNFInit();

#ifdef BUFFER_MODE
  thread_main_loop(nf_local_ctx);
#else
  onvm_nflib_run(nf_local_ctx);
#endif


  onvm_nflib_stop(nf_local_ctx);
  printf("If we reach here, program is ending\n");
  return 0;
}
