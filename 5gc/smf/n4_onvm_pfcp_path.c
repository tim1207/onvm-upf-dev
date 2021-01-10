#include "n4_onvm_pfcp_path.h"

#include <errno.h>
#include "utlt_buff.h"
#include "utlt_debug.h"
#include "pfcp_path.h"
#include "pfcp_message.h"
#include "pfcp_types.h"

#define LINUX_IP_UDP_HDR_LEN \
  (16 + 20 + sizeof(struct rte_udp_hdr))
#define ETHER_IP_UDP_HDR_LEN \
  (RTE_ETHER_HDR_LEN + 20 + sizeof(struct rte_udp_hdr))

void ProcessN4Message(struct rte_mbuf *pkt) {
  PfcpHeader *pfcpHeader = NULL;
  uint32_t outer_header = 0;

  if (pkt->l2_type == 1) {
	  pfcpHeader = (PfcpHeader *)rte_pktmbuf_mtod_offset(pkt, PfcpHeader *,
			  ETHER_IP_UDP_HDR_LEN);
	outer_header = ETHER_IP_UDP_HDR_LEN;
  } else {
	  pfcpHeader = (PfcpHeader *)rte_pktmbuf_mtod_offset(pkt, PfcpHeader *,
			  LINUX_IP_UDP_HDR_LEN);
	outer_header = LINUX_IP_UDP_HDR_LEN;
  }
  Bufblk rcvd_msg;
  rcvd_msg.buf = pfcpHeader;
  rcvd_msg.size = pkt->pkt_len - outer_header;
  rcvd_msg.len = pkt->pkt_len - outer_header;

  Status status;
  Bufblk *bufBlk = NULL;
  Bufblk *recvBufBlk = &rcvd_msg;
  PfcpMessage *pfcpMessage = NULL;
#if 0
	PfcpNode *upf; //TODO(vivek)
	PfcpXact *xact = NULL;
#endif
#if 0
  UpfSession *session = NULL;
#endif
  UTLT_Assert(recvBufBlk, return, "recv buffer no data");
  bufBlk = BufblkAlloc(1, sizeof(PfcpMessage));
  UTLT_Assert(bufBlk, goto freeRecvBuf, "create buffer error");
  pfcpMessage = bufBlk->buf;
  UTLT_Assert(pfcpMessage, goto freeBuf, "pfcpMessage assigned error");

  status = PfcpParseMessage(pfcpMessage, recvBufBlk);
  UTLT_Assert(status == STATUS_OK, goto freeBuf, "PfcpParseMessage error");

#if 0
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
    UTLT_Assert(session, goto freeBuf, "do not find / establish session");
  }

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
      // UpfN4HandleHeartbeatRequest(&pfcpMessage->heartbeatRequest);
      break;
    case PFCP_HEARTBEAT_RESPONSE:
      UTLT_Info("[PFCP] Handle PFCP heartbeat response");
      // UpfN4HandleHeartbeatResponse(&pfcpMessage->heartbeatResponse);
      break;
    case PFCP_ASSOCIATION_SETUP_REQUEST:
      UTLT_Info("[PFCP] Handle PFCP association setup request");
      // UpfN4HandleAssociationSetupRequest(
      //     &pfcpMessage->pFCPAssociationSetupRequest);
      break;
    case PFCP_ASSOCIATION_UPDATE_REQUEST:
      UTLT_Info("[PFCP] Handle PFCP association update request");
      // UpfN4HandleAssociationUpdateRequest(
      //    &pfcpMessage->pFCPAssociationUpdateRequest);
      break;
    case PFCP_ASSOCIATION_RELEASE_RESPONSE:
      UTLT_Info("[PFCP] Handle PFCP association release response");
      // UpfN4HandleAssociationReleaseRequest(
      //     &pfcpMessage->pFCPAssociationReleaseRequest);
      break;
    case PFCP_SESSION_ESTABLISHMENT_REQUEST:
      UTLT_Info("[PFCP] Handle PFCP session establishment request");
      // UpfN4HandleSessionEstablishmentRequest(
      //     session, &pfcpMessage->pFCPSessionEstablishmentRequest);
      break;
    case PFCP_SESSION_MODIFICATION_REQUEST:
      UTLT_Info("[PFCP] Handle PFCP session modification request");
      // UpfN4HandleSessionModificationRequest(
      //     session, &pfcpMessage->pFCPSessionModificationRequest);
      break;
    case PFCP_SESSION_DELETION_REQUEST:
      UTLT_Info("[PFCP] Handle PFCP session deletion request");
      // UpfN4HandleSessionDeletionRequest(
      //     &pfcpMessage->pFCPSessionDeletionRequest);
      break;
    case PFCP_SESSION_REPORT_RESPONSE:
      UTLT_Info("[PFCP] Handle PFCP session report response");
      // UpfN4HandleSessionReportResponse(&pfcpMessage->pFCPSessionReportResponse);
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

int packet_handler(
    struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
    __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
  printf("Vivek handler got called chill %d\n", pkt->l2_type);
  meta->action = ONVM_NF_ACTION_DROP;

  PfcpHeader *pfcpHeader = NULL;

  // TODO(vivek) extract Pfcp body message from IPv4 or IPv6, for now add
  // support for IPv4 only
  if (pkt->l2_type == 1) {
	  pfcpHeader = (PfcpHeader *)rte_pktmbuf_mtod_offset(pkt, PfcpHeader *,
			  ETHER_IP_UDP_HDR_LEN);
  } else {
	  pfcpHeader = (PfcpHeader *)rte_pktmbuf_mtod_offset(pkt, PfcpHeader *,
			  LINUX_IP_UDP_HDR_LEN);
  }
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

static int _pfcpReceiveCB(Sock *sock, void *data) {
#if 0
    //Event event;
    Status status;
    Bufblk *bufBlk = NULL;
    SockAddr from;
    PfcpNode *upf;
    PfcpHeader *pfcpHeader = NULL;

    UTLT_Assert(sock, return -1, "");

    status = PfcpReceiveFrom(sock, &bufBlk, &from);
    if (status != STATUS_OK) {
        if (errno == EAGAIN) {
            return 0;
        }
        return -1;
    }

    UTLT_Assert(from._family == AF_INET, return -1,
                "Support IPv4 only now");

    pfcpHeader = (PfcpHeader *)bufBlk->buf;

    if (pfcpHeader->version > PFCP_VERSION) {
        unsigned char vFail[8];
        PfcpHeader *pfcpOut = (PfcpHeader *)vFail;

        UTLT_Info("Unsupported PFCP version: %d", pfcpHeader->version);
        pfcpOut->flags = (PFCP_VERSION << 5);
        pfcpOut->type = PFCP_VERSION_NOT_SUPPORTED_RESPONSE;
        pfcpOut->length = htons(4);
        pfcpOut->sqn_only = pfcpHeader->sqn_only;
        // TODO: must check localAddress / remoteAddress / fd is correct?
        SockSendTo(sock, vFail, 8);
        BufblkFree(bufBlk);
        return STATUS_ERROR;
    }

    upf = PfcpFindNodeSockAddr(&Self()->upfN4List, &from);
    if (!upf) {
        PfcpFSeid fSeid;
        memset(&fSeid, 0, sizeof(fSeid));
        // IPv4
        if (sock->remoteAddr._family == AF_INET) {
            fSeid.v4 = 1;
            //fSeid.seid = 0; // TOOD: check SEID value
            fSeid.addr4 = from.s4.sin_addr;

            // TODO: check noIpv4, noIpv6, preferIpv4, originally from context.no_ipv4
            upf = PfcpAddNodeWithSeid(&Self()->upfN4List, &fSeid,
                    Self()->pfcpPort, 0, 1, 0);
            if (!upf) {
                // if upf == NULL (allocate error)
                // Count size of upfN4List
                int numOfUpf = 0;
                PfcpNode *n4Node , *nextNode = NULL;
                
                ListForEachSafe(n4Node, nextNode, &Self()->upfN4List) {
                    ++numOfUpf;
                }
                
                UTLT_Error("PFCP Node allocate error, "
                            "there may be too many SMF: %d", numOfUpf);
                BufblkFree(bufBlk);
                return STATUS_ERROR;
            }

            upf->sock = Self()->pfcpSock;
        }
        if (sock->remoteAddr._family == AF_INET6) {
            fSeid.v6 = 1;
            //fSeid.seid = 0;
            fSeid.addr6 = from.s6.sin6_addr;
            upf = PfcpAddNodeWithSeid(&Self()->upfN4List, &fSeid,
                    Self()->pfcpPort, 1, 0, 0);
            UTLT_Assert(upf, BufblkFree(bufBlk); return STATUS_ERROR, "");

            upf->sock = Self()->pfcpSock6;
        }
    }

    UTLT_Assert(upf, BufblkFree(bufBlk); return STATUS_ERROR, "PFCP node not found");

    //event.type = UPF_EVENT_N4_MESSAGE;
    //event.arg0 = (uintptr_t)bufBlk;
    //event.arg1 = (uintptr_t)upf;
    status = EventSend(Self()->eventQ, UPF_EVENT_N4_MESSAGE, 2, bufBlk, upf);
    if (status != STATUS_OK) {
        UTLT_Error("UPF EventSend error");
        BufblkFree(bufBlk);
        return STATUS_ERROR;
    }

    return 0;
#endif
}
