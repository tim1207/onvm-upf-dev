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

#pragma once

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_udp.h>

// #define DEBUG

#define UDP_PORT_FOR_GTP 2152

#define GTP_TPDU 255

// According to 3GPP TS 29.060
typedef struct gtpv1_header {
  uint8_t flags;
  uint8_t type;
  uint16_t length;
  uint32_t teid;
} __attribute__((packed)) gtpv1_t;

#define GTP1_F_NPDU 0x01
#define GTP1_F_SEQ 0x02
#define GTP1_F_EXTHDR 0x04
#define GTP1_F_MASK 0x07

static __rte_always_inline void gtpv1_set_header(gtpv1_t *gtp_hdr,
                                                 uint16_t payload_len,
                                                 uint32_t teid);

/**
 *    Move the GTP Header definition into onvm_nflib/upf.h later
 */
struct gtp_hdr_common {
  uint8_t gtp_hdr_info;
  uint8_t msg_type;
  uint16_t plen;
};

// GTP version 1. (First three bits of gtp_hdr_common->gtp_hdr_info == 1).

// If last 3 bits of gtp_hdr_common->gtp_hdr_info are 0.
// Last three bits:
// Extension header flag, Sequence number extension flag, N-PDU number flag.
struct gtp_hdr_v1_without_last_row {
  uint8_t gtp_hdr_info;
  uint8_t msg_type;
  uint16_t plen;

  uint32_t teid;
};

// If last 3 bits of gtp_hdr_common->gtp_hdr_info > 0.
struct gtp_hdr_v1_with_last_row {
  uint8_t gtp_hdr_info;
  uint8_t msg_type;
  uint16_t plen;

  uint32_t teid;

  uint16_t sequence_number;
  uint8_t n_pdu_number;
  uint8_t next_extension_hdr;
};

// GTP version 2.(First three bits of gtp_hdr_common->gtp_hdr_info == 2).

// If the fifth bit of gtp_hdr_common->gtp_hdr_info is 1.
struct gtp_hdr_v2_with_teid {
  uint8_t gtp_hdr_info;
  uint8_t msg_type;
  uint16_t plen;

  uint32_t teid;
  uint32_t sequence_number_and_spare;
};

// If the fifth bit of gtp_hdr_common->gtp_hdr_info is 0.
struct gtp_hdr_v2_without_teid {
  uint8_t gtp_hdr_info;
  uint8_t msg_type;
  uint16_t plen;

  uint32_t sequence_number_and_spare;
};

/*
        Enum for dereferencing void *.
*/
enum GTP_HDR_TYPE {
  v1_with_last_row,
  v1_without_last_row,
  v2_with_teid,
  v2_without_teid
};

static inline int get_gtp_version(uint8_t gtp_hdr_info) {
  return (gtp_hdr_info >> 5) & 0x3;
}

static inline int parse_gtp_packet(struct rte_mbuf *pkt,
                                   struct rte_udp_hdr *udp_hdr, void **gtp_hdr);

// static inline uint32_t get_teid_gtp_packet(struct rte_mbuf *pkt,
//                                            struct rte_udp_hdr *udp_hdr);

static __rte_always_inline void gtpv1_set_header(gtpv1_t *gtp1_hdr,
                                                 uint16_t payload_len,
                                                 uint32_t teid) {
  /* Bits 8  7  6  5  4  3  2  1
   *    +--+--+--+--+--+--+--+--+
   *    |version |PT| 0| E| S|PN|
   *    +--+--+--+--+--+--+--+--+
   *     0  0  1  1  0  0  0  0
   */
  gtp1_hdr->flags = 0x30;  // v1, GTP-non-prime
  gtp1_hdr->type = GTP_TPDU;
  gtp1_hdr->length = htons(payload_len);
  gtp1_hdr->teid = htonl(teid);
}

static inline int parse_gtp_packet(struct rte_mbuf *pkt,
                                   struct rte_udp_hdr *udp_hdr, void **gtp_hdr) {
  /*
      Parameters:	rte_mbuf *, udp_hdr *, output with pointer to gtp parsed
     header.
      Returns: 	-EINVAL if there's an error, otherwise enum GTP_HDR_TYPE.

      This function parses the GTP header.

      Assumes that the previous header is UDP.
  */
  struct gtp_hdr_common *gtp_hdr_common;
  int ret;

  uint16_t udp_dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);

  // Only consider GTP packet.
  if (udp_dst_port != UDP_PORT_FOR_GTP) {
    return -1 * EINVAL;
  }

  // Parse GTP (first common)
  gtp_hdr_common = rte_pktmbuf_mtod_offset(pkt, struct gtp_hdr_common *,
                                           sizeof(struct rte_ether_hdr) +
                                               sizeof(struct rte_ipv4_hdr) +
                                               sizeof(struct rte_udp_hdr));

  uint8_t gtp_hdr_info = gtp_hdr_common->gtp_hdr_info;
  uint8_t gtp_version = get_gtp_version(gtp_hdr_info);

  bool gtp_version_one_has_last_row = (gtp_hdr_info & 0x7) > 0;
  bool gtp_version_two_has_teid_row = ((gtp_hdr_info >> 3) & 0x1) > 0;

  // GTP parsing.
  if (gtp_version == 1) {
    if (gtp_version_one_has_last_row) {
      *gtp_hdr = rte_pktmbuf_mtod_offset(pkt, struct gtp_hdr_v1_with_last_row *,
                                         sizeof(struct rte_ether_hdr) +
                                             sizeof(struct rte_ipv4_hdr) +
                                             sizeof(struct rte_udp_hdr));
      ret = v1_with_last_row;
    } else {
      *gtp_hdr = rte_pktmbuf_mtod_offset(
          pkt, struct gtp_hdr_v1_without_last_row *,
          sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
              sizeof(struct rte_udp_hdr));
      ret = v1_without_last_row;
    }
  } else if (gtp_version == 2) {
    if (gtp_version_two_has_teid_row) {
      *gtp_hdr = rte_pktmbuf_mtod_offset(pkt, struct gtp_hdr_v2_with_teid *,
                                         sizeof(struct rte_ether_hdr) +
                                             sizeof(struct rte_ipv4_hdr) +
                                             sizeof(struct rte_udp_hdr));
      ret = v2_with_teid;
    } else {
      *gtp_hdr = rte_pktmbuf_mtod_offset(pkt, struct gtp_hdr_v2_without_teid *,
                                         sizeof(struct rte_ether_hdr) +
                                             sizeof(struct rte_ipv4_hdr) +
                                             sizeof(struct rte_udp_hdr));
      ret = v2_without_teid;
    }
  } else {
    return -1 * EINVAL;
  }
  // TODO: GTP Extension Header Parsing
  // TODO: Inner header parsing.
  return ret;
}

static inline int32_t get_teid_gtp_packet(struct rte_mbuf *pkt,
                                          struct rte_udp_hdr *udp_hdr) {
  // extract TEID from struct rte_mbuf *pkt
  void *gtp_hdr;
  int ret = parse_gtp_packet(pkt, udp_hdr, &gtp_hdr);
  if (ret < 0) {
    printf("GTP packet parsing error... drop the packet\n");
    return -1;
  }

  uint32_t teid;
  switch (ret) {
    case v1_with_last_row:
      // printf("v1_with_last_row ");  // Testing.
      teid =
          rte_be_to_cpu_32(((struct gtp_hdr_v1_with_last_row *)gtp_hdr)->teid);
      break;

    case v1_without_last_row:
      // printf("v1_without_last_row ");  // Testing.
      teid = rte_be_to_cpu_32(
          ((struct gtp_hdr_v1_without_last_row *)gtp_hdr)->teid);
      break;

    case v2_with_teid:
      // printf("v2_with_teid ");  // Testing.
      teid = rte_be_to_cpu_32(((struct gtp_hdr_v2_with_teid *)gtp_hdr)->teid);
      break;

    case v2_without_teid:
      printf("v2_without_teid ");  // Testing.
      teid = 0;
      break;

    default:
      // TODO: Drop packet?
      // continue;
      return -1;
  }
  // printf("%" PRIu32 "\n", teid);
  return teid;
}

