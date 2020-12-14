#pragma once

#include "5gc/upf.h"
#include "lib/pfcp_message.h"
#include "onvm_common.h"

void SetNfContext(struct onvm_nf_local_ctx *nf_ctx);

UpfSession *UpfSessionAddByMessage(PfcpMessage *message);

void UpfN4HandleSessionReportResponse(
    PFCPSessionReportResponse *pFCPSessionReportResponse);
void UpfN4HandleHeartbeatRequest(HeartbeatRequest *heartbeatRequest);
void UpfN4HandleHeartbeatResponse(HeartbeatResponse *heartbeatResponse);
Status UpfN4HandleAssociationSetupRequest(
    PFCPAssociationSetupRequest *pFCPAssociationSetupRequest);
void UpfN4HandleAssociationUpdateRequest(
    PFCPAssociationUpdateRequest *pFCPAssociationUpdateRequest);
void UpfN4HandleAssociationReleaseRequest(
    PFCPAssociationReleaseRequest *pFCPAssociationReleaseRequest);
Status UpfN4HandleSessionEstablishmentRequest(
    UpfSession *, PFCPSessionEstablishmentRequest *);
Status UpfN4HandleSessionModificationRequest(
    UpfSession *session, PFCPSessionModificationRequest *request);
void UpfN4HandleSessionDeletionRequest(
    PFCPSessionDeletionRequest *pFCPSessionDeletionRequest);
