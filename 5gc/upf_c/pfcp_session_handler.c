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

  // session = UpfSessionAdd((PfcpUeIpAddr *)
  //             &request->createPDR[0].pDI.uEIPAddress.value,
  //             request->createPDR[0].pDI.networkInstance.value,
  //             ((int8_t *)request->pDNType.value)[0]);
  UTLT_Assert(session, return NULL, "session add error");

  session->smfSeid = *(uint64_t *)request->cPFSEID.value;
  session->upfSeid = seid_pool;
  // session->upfSeid = session->index+1;
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

Status UpfN4HandleCreateFar(UpfSession *session, CreateFAR *createFar) {
  UTLT_Info("Handle Create FAR");

  UTLT_Assert(createFar->fARID.presence, return STATUS_ERROR,
              "Far ID not presence");
  UTLT_Assert(createFar->applyAction.presence, return STATUS_ERROR,
              "Apply Action not presence");

  uint32_t farId = ntohl(*((uint32_t *)createFar->fARID.value));
  if (createFar->fARID.presence) {
    session->far_list[farId].id = farId;
    UTLT_Info("FAR ID: %u", farId);
  }

  if (createFar->applyAction.presence) {
    session->far_list[farId].apply_action =
        *((uint8_t *)(createFar->applyAction.value));
    UTLT_Info("FAR Apply Action: %u", session->far_list[farId].apply_action);
  }

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
  if (createPdr->pDRID.presence) {
    session->pdr_list[pdrID].id = pdrID;
    UTLT_Info("PDR ID: %u", pdrID);
  }

  if (createPdr->precedence.presence) {
    session->pdr_list[pdrID].precedence =
        ntohl(*((uint32_t *)createPdr->precedence.value));
    UTLT_Info("Precedence %u", session->pdr_list[pdrID].precedence);
  }

  if (createPdr->outerHeaderRemoval.presence) {
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

  session->pdr_list[pdrID].active = 1;

  // TODO(vivek): UTLT_Assert(UpfPDRFindByID(pdrID, &upfPdr), return
  // STATUS_ERROR, "PDR
  // ID[%u] does exist in UPF Context", pdrID);

  // // TODO: Need to store the rule in UPF

  // UTLT_Assert(_ConvertCreatePDRTlvToRule(&upfPdr, createPdr) == STATUS_OK,
  //     return STATUS_ERROR, "Convert PDR TLV To Rule is failed");

  // // Using UPDK API
  // UTLT_Assert(Gtpv1TunnelCreatePDR(&upfPdr) == 0, return STATUS_ERROR,
  //     "Gtpv1TunnelCreatePDR failed");

  // // Register PDR to Session
  // UTLT_Assert(UpfPDRRegisterToSession(session, &upfPdr),
  //     return STATUS_ERROR, "UpfPDRRegisterToSession failed");

  // // Set buff relate pdr to session
  // UpfBufPacketAdd(session, pdrID);

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

void UpfN4HandleSessionModificationRequest(
    PFCPSessionModificationRequest *pFCPSessionModificationRequest) {}

void UpfN4HandleSessionDeletionRequest(
    PFCPSessionDeletionRequest *pFCPSessionDeletionRequest) {}
