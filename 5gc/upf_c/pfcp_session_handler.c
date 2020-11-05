#include "pfcp_session_handler.h"

#include <arpa/inet.h>

uint64_t seid_pool = 1;

UpfSession *UpfSessionAddByMessage(PfcpMessage *message) {
  UpfSession *session;

  PFCPSessionEstablishmentRequest *request =
      &message->pFCPSessionEstablishmentRequest;

  if (!request->nodeID.presence) {
    UTLT_Error("no NodeID");
    return NULL;
  }
  if (!request->cPFSEID.presence) {
    UTLT_Error("No cp F-SEID");
    return NULL;
  }
  if (!request->createPDR[0].presence) {
    UTLT_Error("No PDR");
    return NULL;
  }
  if (!request->createFAR[0].presence) {
    UTLT_Error("No FAR");
    return NULL;
  }
  if (!request->pDNType.presence) {
    UTLT_Error("No PDN Type");
    return NULL;
  }
  if (!request->createPDR[0].pDI.presence) {
    UTLT_Error("PDR PDI error");
    return NULL;
  }
  if (!request->createPDR[0].pDI.uEIPAddress.presence) {
    UTLT_Error("UE IP Address error");
    return NULL;
  }
  if (!request->createPDR[0].pDI.networkInstance.presence) {
    UTLT_Error("Interface error");
    return NULL;
  }

  int session_idx = UpfAddPfcpSessionBySeid(seid_pool);
  session = UpfSessionFindBySeid(seid_pool);

  UTLT_Assert(session, return NULL, "session add error");

  session->smfSeid = *(uint64_t *)request->cPFSEID.value;
  session->upfSeid = seid_pool;
  UTLT_Trace("UPF Establishment UPF SEID: %lu", session->upfSeid);
  seid_pool++;
  return session;
}

void UpfN4HandleSessionReportResponse(
    PFCPSessionReportResponse *pFCPSessionReportResponse) {}

void UpfN4HandleHeartbeatRequest(HeartbeatRequest *heartbeatRequest) {}

void UpfN4HandleHeartbeatResponse(HeartbeatResponse *heartbeatResponse) {}

void UpfN4HandleAssociationSetupRequest(
    PFCPAssociationSetupRequest *pFCPAssociationSetupRequest) {}

void UpfN4HandleAssociationUpdateRequest(
    PFCPAssociationUpdateRequest *pFCPAssociationUpdateRequest) {}

void UpfN4HandleAssociationReleaseRequest(
    PFCPAssociationReleaseRequest *pFCPAssociationReleaseRequest) {}

Status UpfN4HandleUpdateFar(UpfSession *session, UpdateFAR *updateFar) {
  UTLT_Debug("Handle Update FAR");

  UTLT_Assert(updateFar->fARID.presence, return STATUS_ERROR,
              "Far ID not presence");

  uint32_t farId = ntohl(*((uint32_t *)updateFar->fARID.value));
  if (session->far_list[farId].active != ACTIVE) {
    UTLT_Error("FAR[%u] does not exist", farId);
    return STATUS_ERROR;
  }

#if 0
    UTLT_Assert(!UpfFARFindByID(farID, &upfFar), return STATUS_ERROR, "FAR ID[%u] does NOT exist in UPF Context", farID);

    UTLT_Assert(_ConvertUpdateFARTlvToRule(&upfFar, updateFar) == STATUS_OK,
        return STATUS_ERROR, "Convert FAR TLV To Rule is failed");

    // Get old apply action to check its changing
    uint8_t oldAction;
    UTLT_Assert(HowToHandleThisPacket(farID, &oldAction) == STATUS_OK, return STATUS_ERROR, "Can NOT find origin FAR action");

    // Using UPDK API
    UTLT_Assert(Gtpv1TunnelUpdateFAR(&upfFar) == 0, return STATUS_ERROR,
        "Gtpv1TunnelUpdateFAR failed");

    // Register FAR to Session
    UTLT_Assert(UpfFARRegisterToSession(session, &upfFar),
        return STATUS_ERROR, "UpfFARRegisterToSession failed");

    // Buffered packet handle
    if ((oldAction & PFCP_FAR_APPLY_ACTION_BUFF)) {
        Sock *sock = &Self()->upSock;

        UpfBufPacket *bufPacket;
        if (upfFar.applyAction & PFCP_FAR_APPLY_ACTION_DROP) {
            UpfPDRNode *node, *nextNode = NULL;
            ListForEachSafe(node, nextNode, &session->pdrList) {
                UTLT_Assert((bufPacket = UpfBufPacketFindByPdrId(node->pdr.pdrId)), continue, "");
                UpfBufPacketRemove(bufPacket);
            }
        } else if (upfFar.applyAction & PFCP_FAR_APPLY_ACTION_FORW) {
            sock->remoteAddr._family = sock->localAddr._family;
            sock->remoteAddr._port = sock->localAddr._port;
            
            if (sock->localAddr._family == AF_INET)
                sock->remoteAddr.s4.sin_addr = upfFar.forwardingParameters.outerHeaderCreation.ipv4;
            else
                UTLT_Warning("Do NOT support IPv6 yet");
            
            UpfPDRNode *node, *nextNode = NULL;
            ListForEachSafe(node, nextNode, &session->pdrList) {
                UTLT_Assert(UpSendPacketByPdrFar(&node->pdr, &upfFar, sock) == STATUS_OK,
                    continue, "UpSendPacketByPdrFar failed: PDR ID[%u], FAR ID[%u]", node->pdr.pdrId, node->pdr.farId);
            }
        }
    }
#endif
  return STATUS_OK;
}
Status UpfN4HandleCreateFar(UpfSession *session, CreateFAR *createFar) {
  UTLT_Info("Handle Create FAR");

  UTLT_Assert(createFar->fARID.presence, return STATUS_ERROR,
              "Far ID not presence");
  UTLT_Assert(createFar->applyAction.presence, return STATUS_ERROR,
              "Apply Action not presence");

  uint32_t farId = ntohl(*((uint32_t *)createFar->fARID.value));

  if (session->far_list[farId].active == ACTIVE) {
    UTLT_Error("FAR[%u] already exists", farId);
    return STATUS_ERROR;
  }

  session->far_list[farId].id = farId;
  UTLT_Info("FAR ID: %u", farId);

  session->far_list[farId].apply_action =
      *((uint8_t *)(createFar->applyAction.value));
  UTLT_Info("FAR Apply Action: %u", session->far_list[farId].apply_action);

  session->far_list[farId].active = ACTIVE;

  return STATUS_OK;
}

Status UpfN4HandleRemoveFar(UpfSession *session, uint32_t nFARID) {
  uint32_t farId = ntohl(nFARID);

  UTLT_Debug("Handle Remove FAR[%u]", farId);
  UTLT_Assert(farId, return STATUS_ERROR, "farId should not be 0");

  if (session->far_list[farId].active != ACTIVE) {
    UTLT_Error("FAR[%u] does not exist", farId);
    return STATUS_ERROR;
  }

  memset(&(session->far_list[farId]), 0, sizeof(session->far_list[farId]));
  return STATUS_OK;
}

Status UpfN4HandleCreatePdr(UpfSession *session, CreatePDR *createPdr) {
  UTLT_Info("Handle Create PDR");

  UTLT_Assert(createPdr->pDRID.presence, return STATUS_ERROR,
              "pdr id not presence");
  UTLT_Assert(createPdr->precedence.presence, return STATUS_ERROR,
              "precedence not presence");
  UTLT_Assert(createPdr->pDI.presence, return STATUS_ERROR, "Pdi not exist");
  UTLT_Assert(createPdr->pDI.sourceInterface.presence, return STATUS_ERROR,
              "PDI SourceInterface not presence");

  uint16_t pdrID = ntohs(*((uint16_t *)createPdr->pDRID.value));

  if (session->pdr_list[pdrID].active == ACTIVE) {
    UTLT_Error("PDR[%u] already active", pdrID);
    return STATUS_ERROR;
  }

  session->pdr_list[pdrID].id = pdrID;

  session->pdr_list[pdrID].precedence =
      ntohl(*((uint32_t *)createPdr->precedence.value));
  UTLT_Info("Precedence %u", session->pdr_list[pdrID].precedence);

  if (createPdr->outerHeaderRemoval.presence) {
    session->pdr_list[pdrID].flag_outer_header_removal = 1;
    session->pdr_list[pdrID].outer_header_removal =
        *((uint8_t *)(createPdr->outerHeaderRemoval.value));
    UTLT_Info("PDR Outer Header Removal: %u",
              session->pdr_list[pdrID].outer_header_removal);
  }

  if (createPdr->fARID.presence) {
    session->pdr_list[pdrID].far_id =
        ntohl(*((uint32_t *)createPdr->fARID.value));
    session->pdr_list[pdrID].far =
        &session->far_list[session->pdr_list[pdrID].far_id];
    UTLT_Info("PDR FAR ID: %u", session->pdr_list[pdrID].far_id);
  }

  session->pdr_list[pdrID].active = ACTIVE;

  return STATUS_OK;
}

Status UpfN4HandleUpdatePdr(UpfSession *session, UpdatePDR *updatePdr) {
  UTLT_Debug("Handle Update PDR");

  UTLT_Assert(updatePdr->pDRID.presence == 1, return STATUS_ERROR,
              "updatePDR no pdrId");

  uint16_t pdrID = ntohs(*((uint16_t *)updatePdr->pDRID.value));
  if (session->pdr_list[pdrID].active != ACTIVE) {
    UTLT_Error("PDR[%u] does not exist", pdrID);
    return STATUS_ERROR;
  }

  return STATUS_OK;
}

Status UpfN4HandleRemovePdr(UpfSession *session, uint16_t nPDRID) {
  uint16_t pdrID = ntohs(nPDRID);

  UTLT_Debug("Handle Remove PDR[%u]", pdrID);
  UTLT_Assert(pdrID, return STATUS_ERROR, "PDR ID cannot be 0");
  UTLT_Assert(session, return STATUS_ERROR, "session not found");

  if (session->pdr_list[pdrID].active != ACTIVE) {
    UTLT_Error("PDR[%u] does not exist", pdrID);
    return STATUS_ERROR;
  }

  memset(&(session->pdr_list[pdrID]), 0, sizeof(session->pdr_list[pdrID]));

  return STATUS_OK;
}

Status UpfN4HandleSessionEstablishmentRequest(
    UpfSession *session, PFCPSessionEstablishmentRequest *request) {
  Status status;
  uint8_t cause = PFCP_CAUSE_REQUEST_ACCEPTED;

  UTLT_Assert(session, return STATUS_ERROR, "Upf Session error");
#if 0
    UTLT_Assert(pfcpXact, return STATUS_ERROR, "pfcpXact error");
#endif

  if (request->createFAR[0].presence) {
    status = UpfN4HandleCreateFar(session, &request->createFAR[0]);
    // TODO: if error, which cause, and pull out the rule from kernel that
    // has been set, maybe need to pull out session as well
    UTLT_Assert(status == STATUS_OK, cause = PFCP_CAUSE_REQUEST_REJECTED,
                "Create FAR error");
  }
  if (request->createFAR[1].presence) {
    status = UpfN4HandleCreateFar(session, &request->createFAR[1]);
    UTLT_Assert(status == STATUS_OK, cause = PFCP_CAUSE_REQUEST_REJECTED,
                "Create FAR error");
  }

  if (request->createURR.presence) {
    // TODO
  }
  if (request->createBAR.presence) {
    // TODO
  }
  if (request->createQER.presence) {
    // TODO
  }

  // The order of PDF should be the lastest
  if (request->createPDR[0].presence) {
    status = UpfN4HandleCreatePdr(session, &request->createPDR[0]);
    UTLT_Assert(status == STATUS_OK, cause = PFCP_CAUSE_REQUEST_REJECTED,
                "Create PDR Error");
  }
  if (request->createPDR[1].presence) {
    status = UpfN4HandleCreatePdr(session, &request->createPDR[1]);
    UTLT_Assert(status == STATUS_OK, cause = PFCP_CAUSE_REQUEST_REJECTED,
                "Create PDR 2 Error");
  }

#if 0
    PfcpHeader header;
    Bufblk *bufBlk = NULL;
    PfcpFSeid *smfFSeid = NULL;

    if (!request->cPFSEID.presence) {
        UTLT_Error("Session Establishment Response: No CP F-SEID");
        cause = PFCP_CAUSE_MANDATORY_IE_MISSING;
    }

    smfFSeid = request->cPFSEID.value;
    session->smfSeid = be64toh(smfFSeid->seid);

    /* Send Response */
    memset(&header, 0, sizeof(PfcpHeader));
    header.type = PFCP_SESSION_ESTABLISHMENT_RESPONSE;
    header.seid = session->smfSeid;

    status = UpfN4BuildSessionEstablishmentResponse(&bufBlk, header.type,
                                                    session, cause, request);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
                "N4 build error");

    status = PfcpXactUpdateTx(pfcpXact, &header, bufBlk);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
                "pfcpXact update TX error");

    status = PfcpXactCommit(pfcpXact);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
                "xact commit error");
#endif

  UTLT_Info("[PFCP] Session Establishment Response");
  return STATUS_OK;
}

Status UpfN4HandleSessionModificationRequest(
    UpfSession *session, PFCPSessionModificationRequest *request) {
  UTLT_Assert(session, return STATUS_ERROR, "Session error");
#if 0
    UTLT_Assert(xact, return STATUS_ERROR, "xact error");
#endif

  Status status;
  PfcpHeader header;
  Bufblk *bufBlk;

  /* Create FAR */
  if (request->createFAR[0].presence) {
    status = UpfN4HandleCreateFar(session, &request->createFAR[0]);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
                "Modification: Create FAR error");
  }
  if (request->createFAR[1].presence) {
    status = UpfN4HandleCreateFar(session, &request->createFAR[1]);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
                "Modification: Create FAR2 error");
  }

  // The order of PDF should be the lastest
  /* Create PDR */
  if (request->createPDR[0].presence) {
    status = UpfN4HandleCreatePdr(session, &request->createPDR[0]);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
                "Modification: Create PDR error");
  }
  if (request->createPDR[1].presence) {
    status = UpfN4HandleCreatePdr(session, &request->createPDR[1]);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
                "Modification: Create PDR2 error");
  }

  /* Update FAR */
  if (request->updateFAR.presence) {
    UTLT_Assert(request->updateFAR.fARID.presence == 1, ,
                "[PFCP] FarId in updateFAR not presence");
    status = UpfN4HandleUpdateFar(session, &request->updateFAR);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
                "Modification: Update FAR error");
  }

  // The order of PDF should be the lastest
  /* Update PDR */
  if (request->updatePDR.presence) {
    UTLT_Assert(request->updatePDR.pDRID.presence == 1, ,
                "[PFCP] PdrId in updatePDR not presence!");
    status = UpfN4HandleUpdatePdr(session, &request->updatePDR);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
                "Modification: Update PDR error");
  }

  /* Remove FAR */
  if (request->removeFAR.presence) {
    UTLT_Assert(request->removeFAR.fARID.presence == 1, ,
                "[PFCP] FarId in removeFAR not presence");
    status = UpfN4HandleRemoveFar(session,
                                  *(uint32_t *)request->removeFAR.fARID.value);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
                "Modification: Remove FAR error");
  }

  // The order of PDF should be the lastest
  /* Remove PDR */
  if (request->removePDR.presence) {
    UTLT_Assert(request->removePDR.pDRID.presence == 1, ,
                "[PFCP] PdrId in removePDR not presence!");
    status = UpfN4HandleRemovePdr(session,
                                  *(uint16_t *)request->removePDR.pDRID.value);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
                "Modification: Remove PDR error");
  }

#if 0
    /* Send Session Modification Response */
    memset(&header, 0, sizeof(PfcpHeader));
    header.type = PFCP_SESSION_MODIFICATION_RESPONSE;
    header.seid = session->smfSeid;

    status = UpfN4BuildSessionModificationResponse(&bufBlk, header.type,
                                                   session, request);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
                "N4 build error");

    status = PfcpXactUpdateTx(xact, &header, bufBlk);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
                "PfcpXactUpdateTx error");

    status = PfcpXactCommit(xact);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
                "PFCP Commit error");
#endif

  UTLT_Info("[PFCP] Session Modification Response");
  return STATUS_OK;
}

void UpfN4HandleSessionDeletionRequest(
    PFCPSessionDeletionRequest *pFCPSessionDeletionRequest) {}
