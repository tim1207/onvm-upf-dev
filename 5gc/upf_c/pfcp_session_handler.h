#pragma once

#include "lib/pfcp_message.h"

void UpfN4HandleSessionReportResponse(
    PFCPSessionReportResponse *pFCPSessionReportResponse);
void UpfN4HandleHeartbeatRequest(HeartbeatRequest *heartbeatRequest);
void UpfN4HandleHeartbeatResponse(HeartbeatResponse *heartbeatResponse);
void UpfN4HandleAssociationSetupRequest(
    PFCPAssociationSetupRequest *pFCPAssociationSetupRequest);
void UpfN4HandleAssociationUpdateRequest(
    PFCPAssociationUpdateRequest *pFCPAssociationUpdateRequest);
void UpfN4HandleAssociationReleaseRequest(
    PFCPAssociationReleaseRequest *pFCPAssociationReleaseRequest);
void UpfN4HandleSessionEstablishmentRequest(
    PFCPSessionEstablishmentRequest *pFCPSessionEstablishmentRequest);
void UpfN4HandleSessionModificationRequest(
    PFCPSessionModificationRequest *pFCPSessionModificationRequest);
void UpfN4HandleSessionDeletionRequest(
    PFCPSessionDeletionRequest *pFCPSessionDeletionRequest);
