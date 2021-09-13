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
#include <rte_gtp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <unistd.h>

#include "gtp.h"
#include "upf_context.h"

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"

#include "interface.h"

#include <time.h>

void get_monotonic_time(struct timespec* ts) {
    clock_gettime(CLOCK_MONOTONIC, ts);
}

long get_time_nano(struct timespec* ts) {
    return (long)ts->tv_sec * 1e9 + ts->tv_nsec;
}

double get_elapsed_time_sec(struct timespec* before, struct timespec* after) {
    double deltat_s  = after->tv_sec - before->tv_sec;
    double deltat_ns = after->tv_nsec - before->tv_nsec;
    return deltat_s + deltat_ns*1e-9;
}

long get_elapsed_time_nano(struct timespec* before, struct timespec* after) {
    return get_time_nano(after) - get_time_nano(before);
}

    struct timespec s;
    struct timespec e;

#define NF_TAG "upf_u"

#if 0
#define SELF_IP RTE_IPV4(10, 100, 200, 3)
#else
#define SELF_IP 63464458
#endif

#define SRC_INTF_ACCESS     0
#define SRC_INTF_CORE       1
#define SRC_INTF_SGI_LAN    2
#define SRC_INTF_CP         3
#define SRC_INTF_NUM        (SRC_INTF_CP + 1)

static inline uint8_t SourceInterfaceToPort (uint8_t interface) {
    switch (interface) {
        case SRC_INTF_ACCESS:
            return 0;
        case SRC_INTF_CORE:
        case SRC_INTF_SGI_LAN:
            return 1;
        case SRC_INTF_CP:
            return -1;
        default:
            return -1;
    }
}

uint64_t seid = 0;
uint16_t pdrId = 0;

UPDK_PDR *GetPdrByUeIpAddress(struct rte_mbuf *pkt, uint32_t ue_ip) {
    UpfSession *session = UpfSessionFindByUeIP(ue_ip);
    UTLT_Assert(session, return NULL, "session not found error");
    UTLT_Assert(session->pdr_list, return NULL, "PDR list not initialized");
    UTLT_Assert(session->pdr_list->len, return NULL, "PDR list contains 0 rules");

    list_node_t *node = session->pdr_list->head;
    UpfPDR *pdr = NULL;
    while (node) {
        pdr = (UpfPDR *) node->val;
        node = node->next;
        if (pdr->flags.pdi) {
            if (pdr->pdi.flags.sourceInterface) {
                if (SourceInterfaceToPort(pdr->pdi.sourceInterface) != pkt->port) {
                    continue;
                }
            }
            break;
        }
    }
    if (pdr) {
        seid = session->upfSeid;
        pdrId = pdr->pdrId;
    }
    return pdr;
}

UPDK_PDR *GetPdrByTeid(struct rte_mbuf *pkt, uint32_t td) {
    UpfSession *session = UpfSessionFindByTeid(td);
    UTLT_Assert(session, return NULL, "session not found error");
    UTLT_Assert(session->pdr_list, return NULL, "PDR list not initialized");
    UTLT_Assert(session->pdr_list->len, return NULL, "PDR list contains 0 rules");
    // printf("TEID HIT\n");
    // get_monotonic_time(&s);
    interface();
    // get_monotonic_time(&e);
    // printf("%lu\n", get_elapsed_time_nano(&s, &e));
    list_node_t *node = session->pdr_list->head;
    UpfPDR *pdr = NULL;
    while (node) {
        pdr = (UpfPDR *) node->val;
        node = node->next;
        if (pdr->flags.pdi) {
            if (pdr->pdi.flags.sourceInterface) {
                if (SourceInterfaceToPort(pdr->pdi.sourceInterface) != pkt->port) {
                    continue;
                }
            }
            break;
        }
    }
    if (pdr) {
        seid = session->upfSeid;
        pdrId = pdr->pdrId;
    }
    return pdr;
}

void HandlePacketWithFar(struct rte_mbuf *pkt, UPDK_FAR *far, struct onvm_pkt_meta *meta) {
#define FAR_ACTION_MASK   0x07
    if (far->flags.applyAction) {
        switch (far->applyAction & FAR_ACTION_MASK) {
            case UPDK_FAR_APPLY_ACTION_DROP:
                meta->action = ONVM_NF_ACTION_DROP;
                break;
            case UPDK_FAR_APPLY_ACTION_FORW:
                if (far->flags.forwardingParameters) {
                    if (far->forwardingParameters.flags.outerHeaderCreation) {
                        UPDK_OuterHeaderCreation *outerHeaderCreation = &(far->forwardingParameters.outerHeaderCreation);
                        switch (outerHeaderCreation->description) {
                            case UPDK_OUTER_HEADER_CREATION_DESCRIPTION_GTPU_UDP_IPV4: {
                                struct rte_gtp_hdr *gtp_hdr =
                                    (struct rte_gtp_hdr *)rte_pktmbuf_prepend(
                                            pkt, (uint16_t) sizeof(struct rte_gtp_hdr));

                                gtp_hdr->msg_type = GTP_TPDU;
                                gtp_hdr->teid = rte_cpu_to_be_32(outerHeaderCreation->teid);
                                gtp_hdr->gtp_hdr_info = 1;

                                struct rte_udp_hdr *udp_hdr =
                                    (struct rte_udp_hdr *)rte_pktmbuf_prepend(
                                            pkt, (uint16_t) sizeof(struct rte_udp_hdr));

                                udp_hdr->src_port = rte_cpu_to_be_16(UDP_PORT_FOR_GTP);
                                udp_hdr->dst_port = rte_cpu_to_be_16(UDP_PORT_FOR_GTP); // outerHeaderCreation->port?
                                udp_hdr->dgram_len = rte_cpu_to_be_16(pkt->data_len); // Or pkt_len?

                                struct rte_ipv4_hdr *ipv4_hdr =
                                    (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(
                                            pkt, (uint16_t) sizeof(struct rte_ipv4_hdr));

                                ipv4_hdr->version_ihl = IPVERSION << 4 | sizeof(struct rte_ipv4_hdr) / RTE_IPV4_IHL_MULTIPLIER;
                                ipv4_hdr->time_to_live = IPDEFTTL;
                                ipv4_hdr->next_proto_id = IPPROTO_UDP;
                                ipv4_hdr->src_addr = SELF_IP;
                                ipv4_hdr->dst_addr = outerHeaderCreation->ipv4.s_addr;
                            }    break;
                            case UPDK_OUTER_HEADER_CREATION_DESCRIPTION_GTPU_UDP_IPV6:
                            case UPDK_OUTER_HEADER_CREATION_DESCRIPTION_UDP_IPV4:
                            case UPDK_OUTER_HEADER_CREATION_DESCRIPTION_UDP_IPV6:
                            default:
                                UTLT_Error("Unknown outer header creation info");
                        }
                    }
                }
                meta->destination = pkt->port ^ 1;
                meta->action = ONVM_NF_ACTION_OUT;
                break;
            case UPDK_FAR_APPLY_ACTION_BUFF:
                break;
            default:
                UTLT_Error("Unspec apply action[%u] in FAR[%u]",
                           far->applyAction,
                           far->farId);
        }
        //TODO(vivek): Complete these actions:
        if (far->applyAction & UPDK_FAR_APPLY_ACTION_NOCP) {
            // Send message to UPF-C
            Event *msg= (Event *) rte_calloc(NULL, 1, sizeof(Event), 0);
            msg->type = UPF_EVENT_SESSION_REPORT;
            msg->arg0 = seid;
            msg->arg1 = pdrId;
            /*
            struct ReportMsg *msg= (struct ReportMsg *) rte_calloc(NULL, 1, sizeof(struct ReportMsg), 0);
            msg->seid = seid;
            msg->pdrId = pdrId;
            */
            onvm_nflib_send_msg_to_nf(2, msg);
        }
        if (far->applyAction & UPDK_FAR_APPLY_ACTION_DUPL) {
            UTLT_Error("Duplicate Apply action: %u not supported, dropping the packet", far->applyAction);
        }
    }
}

static inline void AttachL2Header(struct rte_mbuf *pkt) {
    // Prepend ethernet header
    struct rte_ether_hdr *eth_hdr =
        (struct rte_ether_hdr *)rte_pktmbuf_prepend(
                pkt, (uint16_t)sizeof(struct rte_ether_hdr));

    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    int j = 0;
    for (j = 0; j < RTE_ETHER_ADDR_LEN; ++j) {
        eth_hdr->d_addr.addr_bytes[j] = j;
    }
}

static int packet_handler(struct rte_mbuf *pkt,
                          struct onvm_pkt_meta *meta,
                          struct onvm_nf_local_ctx *nf_local_ctx) {
    meta->action = ONVM_NF_ACTION_DROP;
    struct rte_ipv4_hdr *iph = onvm_pkt_ipv4_hdr(pkt);

    if (iph == NULL) {
        return 0;
    }

    UPDK_PDR *pdr = NULL;

    // Step 1: Identify if it is a uplink packet or downlink packet
    if (iph->dst_addr == SELF_IP) {  //
        struct rte_udp_hdr *udp_header = onvm_pkt_udp_hdr(pkt);
        if (udp_header == NULL) {
            return 0;
        }
        // invariant(dst_port == GTPV1_PORT);
        // extract TEID from
        // Step 2: Get PDR rule
        uint32_t teid = get_teid_gtp_packet(pkt, udp_header);
        get_monotonic_time(&s);
        pdr = GetPdrByTeid(pkt, teid);
        get_monotonic_time(&e);
        printf("%lu\n", get_elapsed_time_nano(&s, &e));
    } else {
        // Step 2: Get PDR rule
        pdr = GetPdrByUeIpAddress(pkt, rte_cpu_to_be_32(iph->dst_addr));
    }

    if (!pdr) {
        printf("no PDR found for %pI4, skip\n", &iph->dst_addr);
        // TODO(vivek): what to do?
        return 0;
    }

    UPDK_FAR *far;
    far = pdr->far;

    if (!far) {
        printf("There is no FAR related to PDR[%u]\n", pdr->pdrId);
        meta->action = ONVM_NF_ACTION_DROP;
        return 0;
    }

    if (pdr->flags.outerHeaderRemoval) {
        uint16_t outerHeaderLen = 0;
        switch (pdr->outerHeaderRemoval) {
            case OUTER_HEADER_REMOVAL_GTP_IP4: {
                outerHeaderLen = sizeof(struct rte_ether_hdr) +
                                 sizeof(struct rte_ipv4_hdr) +
                                 sizeof(struct rte_udp_hdr) +
                                 12; // GTPv1 Header
                rte_pktmbuf_adj(pkt, outerHeaderLen);
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
    }

    HandlePacketWithFar(pkt, far, meta);
#if 0
    AttachL2Header(pkt);
#endif
    return 0;
}

int main(int argc, char *argv[]) {
    int arg_offset;
    struct onvm_nf_local_ctx *nf_local_ctx;
    struct onvm_nf_function_table *nf_function_table;

    nf_local_ctx = onvm_nflib_init_nf_local_ctx();
    onvm_nflib_start_signal_handler(nf_local_ctx, NULL);
    nf_function_table = onvm_nflib_init_nf_function_table();
    nf_function_table->pkt_handler = &packet_handler;

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

    UpfSessionPoolInit ();
    UeIpToUpfSessionMapInit();
    TeidToUpfSessionMapInit();
    createCLS();
    onvm_nflib_run(nf_local_ctx);

    onvm_nflib_stop(nf_local_ctx);
    printf("If we reach here, program is ending\n");
    return 0;
}
