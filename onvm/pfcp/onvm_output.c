#include "onvm_output.h"

#include "onvm_nflib.h"

#include "utlt_debug.h"

#include <errno.h>

struct onvm_nf_local_ctx *ctx;

void OnvmSetNfContext(struct onvm_nf_local_ctx *nf_ctx) { ctx = nf_ctx; }

Status OnvmSend(char *buff, int service_id, int buff_length) {
  uint32_t i;
  struct rte_mempool *pktmbuf_pool;

  pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
  if (pktmbuf_pool == NULL) {
    return STATUS_ERROR;
  }

  struct onvm_pkt_meta *pmeta;
  struct rte_ether_hdr *ehdr;
  struct rte_udp_hdr *udphdr;
  struct rte_ipv4_hdr *ipv4_hdr;

  struct rte_mbuf *pkt = rte_pktmbuf_alloc(pktmbuf_pool);
  if (pkt == NULL) {
    return STATUS_ERROR;
  }

  rte_pktmbuf_prepend(pkt, buff_length);
  rte_memcpy(rte_pktmbuf_mtod(pkt, char *), buff, buff_length);

  udphdr = (struct rte_udp_hdr *)rte_pktmbuf_prepend(
      pkt, sizeof(struct rte_udp_hdr));
  udphdr->src_port = rte_cpu_to_be_16(8805);
  udphdr->dst_port = rte_cpu_to_be_16(8805);
  udphdr->dgram_len = rte_cpu_to_be_16(buff_length + 8);

  ipv4_hdr = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(
      pkt, sizeof(struct rte_ipv4_hdr));
  ipv4_hdr->version_ihl =
      IPVERSION << 4 | sizeof(struct rte_ipv4_hdr) / RTE_IPV4_IHL_MULTIPLIER;
  ipv4_hdr->time_to_live = IPDEFTTL;
  ipv4_hdr->next_proto_id = 17;
  ipv4_hdr->dst_addr = rte_cpu_to_be_32(2130706433);
  ipv4_hdr->src_addr = rte_cpu_to_be_32(2130706433);
  ipv4_hdr->total_length = rte_cpu_to_be_32(
      buff_length + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr));

  /*set up ether header and set new packet size*/
  ehdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(pkt, RTE_ETHER_HDR_LEN);

  /*using manager mac addr for source
   *using input string for dest addr
   */

  if (onvm_get_macaddr(0, &ehdr->s_addr) == -1) {
    onvm_get_fake_macaddr(&ehdr->s_addr);
  }

  for (i = 0; i < RTE_ETHER_ADDR_LEN; ++i) {
    ehdr->d_addr.addr_bytes[i] = i;
  }

  ehdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

  // fill out the meta data of the packet
  pmeta = onvm_get_pkt_meta(pkt);
  pmeta->destination = service_id;
  pmeta->action = ONVM_NF_ACTION_TONF;
  pkt->hash.rss = 0;
  pkt->port = 0;
#if 0
  pkt->data_len = buff_length + ETHER_IP_UDP_HDR_LEN;  //???
  /* Copy the packet into the rte_mbuf data section */
#endif

  // send out the generated packet
  int s = onvm_nflib_return_pkt(ctx->nf, pkt);
  if (s < 0) {
    return STATUS_ERROR;
  }

  return STATUS_OK;
}
