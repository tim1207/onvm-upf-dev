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

#include "5gc/upf.h"
#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"

// #include "lib/n4_pfcp_handler.h"
#include "lib/pfcp_message.h"
// #include "lib/pfcp_node.h"
// #include "lib/pfcp_xact.h"
// #include "lib/upf_context.h"

#include "pfcp_session_handler.h"

#define NF_TAG "upf_c"

void ProcessN4Message(struct rte_mbuf *pkt) {
  PfcpHeader *pfcpHeader = NULL;

  pfcpHeader =
      (PfcpHeader *)rte_pktmbuf_mtod_offset(pkt, PfcpHeader *, 16 + 8 + 20);

  Bufblk rcvd_msg;
  rcvd_msg.buf = pfcpHeader;
  rcvd_msg.size = pkt->pkt_len - (16 + 8 + 20);
  rcvd_msg.len = pkt->pkt_len - (16 + 8 + 20);

  Status status;
  Bufblk *bufBlk = NULL;
  Bufblk *recvBufBlk = &rcvd_msg;
  PfcpMessage *pfcpMessage = NULL;
#if 0
	PfcpNode *upf; //TODO(vivek)
	PfcpXact *xact = NULL;
#endif
  UpfSession *session = NULL;

  UTLT_Assert(recvBufBlk, return, "recv buffer no data");
  bufBlk = BufblkAlloc(1, sizeof(PfcpMessage));
  UTLT_Assert(bufBlk, goto freeRecvBuf, "create buffer error");
  pfcpMessage = bufBlk->buf;
  UTLT_Assert(pfcpMessage, goto freeBuf, "pfcpMessage assigned error");

  status = PfcpParseMessage(pfcpMessage, recvBufBlk);
  UTLT_Assert(status == STATUS_OK, goto freeBuf, "PfcpParseMessage error");

  if (pfcpMessage->header.seidP) {
    // if SEID presence
    if (!pfcpMessage->header.seid) {
      // without SEID
      if (pfcpMessage->header.type == PFCP_SESSION_ESTABLISHMENT_REQUEST) {
        session = UpfSessionAddByMessage(pfcpMessage);
      } else {
        UTLT_Assert(0, goto freeBuf, "no SEID but not SESSION ESTABLISHMENT");
      }
    } else {
      // with SEID
      session = UpfSessionFindBySeid(pfcpMessage->header.seid);
    }
  }
  UTLT_Assert(session, goto freeBuf, "do not find / establish session");

#if 0
    if (pfcpMessage->header.type != PFCP_SESSION_REPORT_RESPONSE) {
			session->pfcpNode = upf;
    }

		status = PfcpXactReceive(session->pfcpNode,
				&pfcpMessage->header, &xact);
    UTLT_Assert(status == STATUS_OK, goto freeBuf, "");
  } else {
		status = PfcpXactReceive(upf, &pfcpMessage->header, &xact);
    UTLT_Assert(status == STATUS_OK, goto freeBuf, "");
  }
#endif

  switch (pfcpMessage->header.type) {
    case PFCP_HEARTBEAT_REQUEST:
      UTLT_Info("[PFCP] Handle PFCP heartbeat request");
      UpfN4HandleHeartbeatRequest(&pfcpMessage->heartbeatRequest);
      break;
    case PFCP_HEARTBEAT_RESPONSE:
      UTLT_Info("[PFCP] Handle PFCP heartbeat response");
      UpfN4HandleHeartbeatResponse(&pfcpMessage->heartbeatResponse);
      break;
    case PFCP_ASSOCIATION_SETUP_REQUEST:
      UTLT_Info("[PFCP] Handle PFCP association setup request");
      UpfN4HandleAssociationSetupRequest(
          &pfcpMessage->pFCPAssociationSetupRequest);
      break;
    case PFCP_ASSOCIATION_UPDATE_REQUEST:
      UTLT_Info("[PFCP] Handle PFCP association update request");
      UpfN4HandleAssociationUpdateRequest(
          &pfcpMessage->pFCPAssociationUpdateRequest);
      break;
    case PFCP_ASSOCIATION_RELEASE_RESPONSE:
      UTLT_Info("[PFCP] Handle PFCP association release response");
      UpfN4HandleAssociationReleaseRequest(
          &pfcpMessage->pFCPAssociationReleaseRequest);
      break;
    case PFCP_SESSION_ESTABLISHMENT_REQUEST:
      UTLT_Info("[PFCP] Handle PFCP session establishment request");
      UpfN4HandleSessionEstablishmentRequest(
          session, &pfcpMessage->pFCPSessionEstablishmentRequest);
      break;
    case PFCP_SESSION_MODIFICATION_REQUEST:
      UTLT_Info("[PFCP] Handle PFCP session modification request");
      UpfN4HandleSessionModificationRequest(
          session, &pfcpMessage->pFCPSessionModificationRequest);
      break;
    case PFCP_SESSION_DELETION_REQUEST:
      UTLT_Info("[PFCP] Handle PFCP session deletion request");
      UpfN4HandleSessionDeletionRequest(
          &pfcpMessage->pFCPSessionDeletionRequest);
      break;
    case PFCP_SESSION_REPORT_RESPONSE:
      UTLT_Info("[PFCP] Handle PFCP session report response");
      UpfN4HandleSessionReportResponse(&pfcpMessage->pFCPSessionReportResponse);
      break;
    default:
      UTLT_Error("No implement pfcp type: %d", pfcpMessage->header.type);
  }
freeBuf:
  PfcpStructFree(pfcpMessage);
  BufblkFree(bufBlk);
freeRecvBuf:
  BufblkFree(recvBufBlk);
}

static int packet_handler(
    struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
    __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
  meta->action = ONVM_NF_ACTION_DROP;
  struct rte_ipv4_hdr *ipv4_hdr;
  ipv4_hdr = onvm_pkt_ipv4_hdr(pkt);
  ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, 16);

  PfcpHeader *pfcpHeader = NULL;

  // TODO(vivek) extract Pfcp body message from IPv4 or IPv6, for now add
  // support for IPv4 only
  pfcpHeader =
      (PfcpHeader *)rte_pktmbuf_mtod_offset(pkt, PfcpHeader *, 16 + 8 + 20);
  pfcpHeader->length = ntohs(pfcpHeader->length);

  // TODO(vivek): verify the PFCP version
  if (pfcpHeader->version > PFCP_VERSION) {
    unsigned char vFail[8];
    PfcpHeader *pfcpOut = (PfcpHeader *)vFail;

    UTLT_Info("Unsupported PFCP version: %d", pfcpHeader->version);
    pfcpOut->flags = (PFCP_VERSION << 5);
    pfcpOut->type = PFCP_VERSION_NOT_SUPPORTED_RESPONSE;
    pfcpOut->length = htons(4);
    pfcpOut->sqn_only = pfcpHeader->sqn_only;
    // TODO(vivek): Send to back to SMF
    // TODO(free5gc): must check localAddress / remoteAddress / fd is correct?
    // SockSendTo(sock, vFail, 8);
    // BufblkFree(bufBlk);
    return 0;
  }

  ProcessN4Message(pkt);

  return 0;
}

int main(int argc, char *argv[]) {
  Status status;

  status = BufblkPoolInit();
  if (status != STATUS_OK) {
    rte_exit(EXIT_FAILURE, "Failed BufblkPoolInit\n");
    return status;
  }

  SetLogLevel(5);

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

  argc -= arg_offset;
  argv += arg_offset;

  PfcpSessionTableNFInit();

  onvm_nflib_run(nf_local_ctx);

  onvm_nflib_stop(nf_local_ctx);
  printf("If we reach here, program is ending\n");
  return 0;
}
