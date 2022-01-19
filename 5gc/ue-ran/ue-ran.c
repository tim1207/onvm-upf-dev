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
 * bridge.c - send all packets from one port out the other.
 ********************************************************************/

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_gtp.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"

#define NF_TAG "bridge"

/* number of package between each print */
static uint32_t print_delay = 1000000;

/*
 * Print a usage message
 */
static void
usage(const char *progname) {
        printf("Usage:\n");
        printf("%s [EAL args] -- [NF_LIB args] -- -p <print_delay>\n", progname);
        printf("%s -F <CONFIG_FILE.json> [EAL args] -- [NF_LIB args] -- [NF args]\n\n", progname);
        printf("Flags:\n");
        printf(" - `-p <print_delay>`: number of packets between each print, e.g. `-p 1` prints every packets.\n");
}

/*
 * Parse the application arguments.
 */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
        int c;

        while ((c = getopt(argc, argv, "p:")) != -1) {
                switch (c) {
                        case 'p':
                                print_delay = strtoul(optarg, NULL, 10);
                                break;
                        case '?':
                                usage(progname);
                                if (optopt == 'p')
                                        RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                                else if (isprint(optopt))
                                        RTE_LOG(INFO, APP, "Unknown option `-%c'.\n", optopt);
                                else
                                        RTE_LOG(INFO, APP, "Unknown option character `\\x%x'.\n", optopt);
                                return -1;
                        default:
                                usage(progname);
                                return -1;
                }
        }
        return optind;
}

/*
 * This function displays stats. It uses ANSI terminal codes to clear
 * screen when called. It is called from a single non-master
 * thread in the server process, when the process is run with more
 * than one lcore enabled.
 */
static void
do_stats_display(struct rte_mbuf *pkt) {
        const char clr[] = {27, '[', '2', 'J', '\0'};
        const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};
        static uint64_t pkt_process = 0;

        struct rte_ipv4_hdr *ip;

        pkt_process += print_delay;

        /* Clear screen and move to top left */
        printf("%s%s", clr, topLeft);

        printf("PACKETS\n");
        printf("-----\n");
        printf("Port : %d\n", pkt->port);
        printf("Size : %d\n", pkt->pkt_len);
        printf("Type : %d\n", pkt->packet_type);
        printf("Number of packet processed : %" PRIu64 "\n", pkt_process);

        ip = onvm_pkt_ipv4_hdr(pkt);
        if (ip != NULL) {
                onvm_pkt_print(pkt);
        } else {
                printf("Not IP4\n");
        }

        printf("\n\n");
}

static struct rte_ether_addr l2fwd_ports_eth_addr[3];
static struct rte_ether_addr f4_eth;

static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        static uint32_t counter = 0;
        if (counter++ == print_delay) {
                do_stats_display(pkt);
                counter = 0;
        }

        if (pkt->port == 0) {
                struct rte_ether_hdr *eth = (struct rte_ether_hdr *) rte_pktmbuf_adj(pkt, 44);
                eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
                rte_ether_addr_copy(&l2fwd_ports_eth_addr[0], &eth->s_addr);
                rte_ether_addr_copy(&l2fwd_ports_eth_addr[1], &eth->d_addr);
        } else {
                int outerHeaderLen = 20 + 8 + 8; // sizeof(struct rte_ipv4_hdr) +
                                                 // sizeof(struct rte_udp_hdr) +
                                                 // sizeof(struct rte_gtp_hdr);
                int payloadLen = 0;
                payloadLen = pkt->data_len - RTE_ETHER_HDR_LEN;
                rte_pktmbuf_prepend(pkt, outerHeaderLen);
                
                struct rte_gtp_hdr *gtp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_gtp_hdr *, RTE_ETHER_HDR_LEN + 20 + 8);
                gtp_hdr->msg_type = 0xff;
                gtp_hdr->teid = rte_cpu_to_be_32(1);
                gtp_hdr->plen = rte_cpu_to_be_16(payloadLen);
                gtp_hdr->gtp_hdr_info = 0x30;

                struct rte_udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_udp_hdr *, RTE_ETHER_HDR_LEN + 20);
                onvm_pkt_fill_udp(udp_hdr, RTE_GTPU_UDP_PORT, RTE_GTPU_UDP_PORT, payloadLen + sizeof(struct rte_gtp_hdr)); 

                struct rte_ipv4_hdr *ip_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, RTE_ETHER_HDR_LEN);
                onvm_pkt_fill_ipv4(ip_hdr, RTE_IPV4(10, 100, 200, 1), RTE_IPV4(10, 100, 200, 3), IPPROTO_UDP);
                ip_hdr->total_length = rte_cpu_to_be_16(payloadLen + outerHeaderLen);
               
                struct rte_ether_hdr *eth = rte_pktmbuf_mtod_offset(pkt, struct rte_ether_hdr *, 0); 
                eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
                rte_ether_addr_copy(&l2fwd_ports_eth_addr[0], &eth->s_addr);
                rte_ether_addr_copy(&f4_eth, &eth->d_addr);
                ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
        }
        meta->destination = 1 - pkt->port;
        meta->action = ONVM_NF_ACTION_OUT;
        return 0;
}

int
main(int argc, char *argv[]) {
        int arg_offset;
        struct onvm_nf_local_ctx *nf_local_ctx;
        struct onvm_nf_function_table *nf_function_table;
        const char *progname = argv[0];

        nf_local_ctx = onvm_nflib_init_nf_local_ctx();
        onvm_nflib_start_signal_handler(nf_local_ctx, NULL);

        nf_function_table = onvm_nflib_init_nf_function_table();
        nf_function_table->pkt_handler = &packet_handler;

        if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG, nf_local_ctx, nf_function_table)) < 0) {
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

        if (parse_app_args(argc, argv, progname) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
        }

        int ret;
        int ii = 0;
        for (ii = 0; ii < 2; ii++) { 
            ret = rte_eth_macaddr_get(ii, &l2fwd_ports_eth_addr[ii]);
            if (ret < 0)
                rte_exit(EXIT_FAILURE, "Cannot get MAC address: err=%d, port=%u\n", ret, ii);
        }

        // 5e:3a:0a:5b:8f:fc
        l2fwd_ports_eth_addr[2].addr_bytes[0] = 0x5e;
        l2fwd_ports_eth_addr[2].addr_bytes[1] = 0x3a;
        l2fwd_ports_eth_addr[2].addr_bytes[2] = 0x0a;
        l2fwd_ports_eth_addr[2].addr_bytes[3] = 0x5b;
        l2fwd_ports_eth_addr[2].addr_bytes[4] = 0x8f;
        l2fwd_ports_eth_addr[2].addr_bytes[5] = 0xfc;

        // Core network MAC: 8c:dc:d4:ac:6b:65
        f4_eth.addr_bytes[0] = 0x8c;
        f4_eth.addr_bytes[1] = 0xdc;
        f4_eth.addr_bytes[2] = 0xd4;
        f4_eth.addr_bytes[3] = 0xac;
        f4_eth.addr_bytes[4] = 0x6b;
        f4_eth.addr_bytes[5] = 0x65;


        onvm_nflib_run(nf_local_ctx);

        onvm_nflib_stop(nf_local_ctx);
        printf("If we reach here, program is ending\n");
        return 0;
}
