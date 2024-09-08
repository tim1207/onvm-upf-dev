#define TRACE_MODULE _n4_dispatcher

#include "utlt_debug.h"
#include "utlt_event.h"
#include "n4_onvm_pfcp_handler.h"
#include "pfcp_xact.h"
#include "pfcp_path.h"
#include "n4_onvm_pfcp_build.h"
#include "upf_context.h"
#include "pfcp_message.c"

// String table for PFCP message types
static const char* StringTable[] = {
    "Reserved",
    "CreatePDR",
    "PDI",
    "CreateFAR",
    "ForwardingParameters",
    "DuplicatingParameters",
    "CreateURR",
    "CreateQER",
    "CreatedPDR",
    "UpdatePDR",
    "UpdateFAR",
    "UpdateForwardingParameters",
    "UpdateBARPFCPSessionReportResponse",
    "UpdateURR",
    "UpdateQER",
    "RemovePDR",
    "RemoveFAR",
    "RemoveURR",
    "RemoveQER",
    "Cause",
    "SourceInterface",
    "FTEID",
    "NetworkInstance",
    "SDFFilter",
    "ApplicationID",
    "GateStatus",
    "MBR",
    "GBR",
    "QERCorrelationID",
    "Precedence",
    "TransportLevelMarking",
    "VolumeThreshold",
    "TimeThreshold",
    "MonitoringTime",
    "SubsequentVolumeThreshold",
    "SubsequentTimeThreshold",
    "InactivityDetectionTime",
    "ReportingTriggers",
    "RedirectInformation",
    "ReportType",
    "OffendingIE",
    "ForwardingPolicy",
    "DestinationInterface",
    "UPFunctionFeatures",
    "ApplyAction",
    "DownlinkDataServiceInformation",
    "DownlinkDataNotificationDelay",
    "DLBufferingDuration",
    "DLBufferingSuggestedPacketCount",
    "PFCPSMReqFlags",
    "PFCPSRRspFlags",
    "LoadControlInformation", 
    "SequenceNumber",
    "Metric",
    "OverloadControlInformation",
    "Timer",
    "PacketDetectionRuleID",
    "FSEID",
    "ApplicationIDsPFDs", 
    "PFDContext",
    "NodeID",
    "PFDContents",
    "MeasurementMethod",
    "UsageReportTrigger",
    "MeasurementPeriod",
    "FQCSID",
    "VolumeMeasurement",
    "DurationMeasurement",
    "ApplicationDetectionInformation",
    "TimeOfFirstPacket",
    "TimeOfLastPacket",
    "QuotaHoldingTime",
    "DroppedDLTrafficThreshold",
    "VolumeQuota",
    "TimeQuota",
    "StartTime",
    "EndTime",
    "QueryURR",
    "UsageReportPFCPSessionModificationResponse",
    "UsageReportPFCPSessionDeletionResponse",
    "UsageReportPFCPSessionReportRequest",
    "URRID",
    "LinkedURRID",
    "DownlinkDataReport", 
    "OuterHeaderCreation",
    "CreateBAR",
    "UpdateBARPFCPSessionModificationRequest",
    "RemoveBAR",
    "BARID",
    "CPFunctionFeatures",
    "UsageInformation",
    "ApplicationInstanceID",
    "FlowInformation",
    "UEIPAddress",
    "PacketRate",
    "OuterHeaderRemoval",
    "RecoveryTimeStamp",
    "DLFlowLevelMarking",
    "HeaderEnrichment",
    "ErrorIndicationReport",
    "MeasurementInformation",
    "NodeReportType",
    "UserPlanePathFailureReport", 
    "RemoteGTPUPeer",
    "URSEQN",
    "UpdateDuplicatingParameters",
    "ActivatePredefinedRules",
    "DeactivatePredefinedRules",
    "FARID",
    "QERID",
    "OCIFlags",
    "PFCPAssociationReleaseRequest",
    "GracefulReleasePeriod",
    "PDNType",
    "FailedRuleID",
    "TimeQuotaMechanism",
    "UserPlaneIPResourceInformation",
    "UserPlaneInactivityTimer",
    "AggregatedURRs",
    "Multiplier",
    "AggregatedURRID",
    "SubsequentVolumeQuota",
    "SubsequentTimeQuota",
    "RQI",
    "QFI",
    "QueryURRReference",
    "AdditionalUsageReportsInformation",
    "CreateTrafficEndpoint",
    "CreatedTrafficEndpoint",
    "UpdateTrafficEndpoint",
    "RemoveTrafficEndpoint", 
    "TrafficEndpointID",
    "EthernetPacketFilter",
    "MACAddress",
    "CTAG",
    "STAG",
    "Ethertype",
    "Proxying",
    "EthernetFilterID",
    "EthernetFilterProperties",
    "SuggestedBufferingPacketsCount",
    "UserID",
    "EthernetPDUSessionInformation",
    "EthernetTrafficInformation",
    "MACAddressesDetected",
    "MACAddressesRemoved",
    "EthernetInactivityTimer",
    "AdditionalMonitoringTime", 
    "EventInformation",
    "EventReporting",
    "EventID",
    "EventThreshold",
    "TraceInformation",
    "FramedRoute",
    "FramedRouting",
    "FramedIPv6Route",
    "HeartbeatRequest",
    "HeartbeatResponse",
    "PFCPPFDManagementRequest",
    "PFCPPFDManagementResponse", 
    "PFCPAssociationSetupRequest",
    "PFCPAssociationSetupResponse", 
    "PFCPAssociationUpdateRequest",
    "PFCPAssociationUpdateResponse",
    "PFCPAssociationReleaseResponse", 
    "PFCPNodeReportRequest",
    "PFCPNodeReportResponse",
    "PFCPSessionSetDeletionRequest",
    "PFCPSessionSetDeletionResponse",
    "PFCPSessionEstablishmentRequest", 
    "PFCPSessionEstablishmentResponse", 
    "PFCPSessionModificationRequest", 
    "PFCPSessionModificationResponse",
    "PFCPSessionDeletionRequest",
    "PFCPSessionDeletionResponse",
    "PFCPSessionReportRequest",
    "PFCPSessionReportResponse",

};

// Function to get string from table
const char* GetStringFromTable(int index) {
    if (index >= 0 && index < sizeof(StringTable) / sizeof(StringTable[0])) {
        return StringTable[index];
    }
    return NULL;
}



int MyTlvParseMessage(void * msg, IeDescription * msgDes, void * buff, int buffLen,int dashTime);

void UpfDispatcher(const Event *event) {
    switch ((UpfEvent)event->type) {
        case UPF_EVENT_SESSION_REPORT: {
            Status status;
            PfcpHeader header;
            Bufblk *bufBlk = NULL;
            PfcpXact *xact = NULL;

            uint64_t seid = (uint64_t)event->arg0;
            uint16_t pdrId = (uint16_t)event->arg1;

            UpfSession *session = UpfSessionFindBySeid(seid);
            UTLT_Assert(session != NULL, return,
                        "Session not find by seid: %d", seid);

            //to check if srr has been sent
            if(session->srr_flag == true){
                UTLT_Info("PFCP Session Report Request has been sent\n");
                return;
            }

            session->srr_flag = true;

            memset(&header, 0, sizeof(PfcpHeader));
            header.type = PFCP_SESSION_REPORT_REQUEST;
            header.seid = seid;

            status = UpfN4BuildSessionReportRequestDownlinkDataReport(&bufBlk,
                                                                      header.type,
                                                                      session,
                                                                      pdrId);
            UTLT_Assert(status == STATUS_OK, return,
                        "Build Session Report Request error");
            
            UTLT_Warning("Send Session Report Request");
            xact = PfcpXactLocalCreate(session->pfcpNode, &header, bufBlk);
            UTLT_Assert(xact, return, "pfcpXactLocalCreate error");

            status = PfcpXactCommit(xact);
            UTLT_Assert(status == STATUS_OK, return, "xact commit error");

            BufblkFree(bufBlk);

            break;
        }
        case UPF_EVENT_N4_MESSAGE: {
            Status status;
            Bufblk *bufBlk = NULL;
            Bufblk *recvBufBlk = (Bufblk *)event->arg0;
            PfcpNode *upf = (PfcpNode *)event->arg1;
            PfcpMessage *pfcpMessage = NULL;
            PfcpXact *xact = NULL;
            UpfSession *session = NULL;

            UTLT_Assert(recvBufBlk, return, "recv buffer no data");
            bufBlk = BufblkAlloc(1, sizeof(PfcpMessage));
            UTLT_Assert(bufBlk, return, "create buffer error");
            pfcpMessage = bufBlk->buf;
            UTLT_Assert(pfcpMessage, goto freeBuf, "pfcpMessage assigned error");


            // here is for debug
            Bufblk *MybufBlk = NULL;
            Bufblk *MyrecvBufBlk = (Bufblk *)event->arg0;
            PfcpMessage *MypfcpMessage = NULL;
            MybufBlk = BufblkAlloc(1, sizeof(PfcpMessage));
            MypfcpMessage = MybufBlk->buf;

            PfcpHeader *Myheader = NULL;
            uint16_t Mysize = 0;
            void *Mybody = NULL;
            uint16_t MybodyLen = 0;

            Myheader = MyrecvBufBlk->buf;
            memset(MypfcpMessage, 0, sizeof(PfcpMessage));

            if (Myheader->seidP) {
                Mysize = PFCP_HEADER_LEN; //16
            } else {
                Mysize = PFCP_HEADER_LEN - PFCP_SEID_LEN; // 8
            }
            memcpy(&MypfcpMessage->header, MyrecvBufBlk->buf, Mysize);
            Mybody = MyrecvBufBlk->buf + Mysize;
            MybodyLen = MyrecvBufBlk->len - Mysize;

            if (Myheader->seidP) {
                UTLT_Info("header->seid: %lu\n", be64toh(Myheader->seid));
                MypfcpMessage->header.seid = be64toh(MypfcpMessage->header.seid);
            } else { 
                UTLT_Info("header->sqn: %u\n", Myheader->sqn);
                UTLT_Info("header->sqn_only: %u\n", Myheader->sqn_only);
                MypfcpMessage->header.sqn = pfcpMessage->header.sqn_only;
                MypfcpMessage->header.sqn_only = pfcpMessage->header.sqn_only;
            }

            switch (MypfcpMessage->header.type)
            {
            case PFCP_SESSION_ESTABLISHMENT_REQUEST:
                UTLT_Info("PFCP_SESSION_ESTABLISHMENT_REQUEST");
                //MyTlvParseMessage(MypfcpMessage, &ieDescriptionTable[PFCP_SESSION_ESTABLISHMENT_REQUEST + 155 - (50-15) - 1], Mybody, MybodyLen,1);
                break;
            case PFCP_SESSION_MODIFICATION_REQUEST:
                UTLT_Info("PFCP_SESSION_MODIFICATION_REQUEST");
                //MyTlvParseMessage(MypfcpMessage, &ieDescriptionTable[PFCP_SESSION_MODIFICATION_REQUEST + 155 - (50-15) - 1], Mybody, MybodyLen,1);
                break;
            
            default:
                UTLT_Info("default");
                break;
            }

            status = PfcpParseMessage(pfcpMessage, recvBufBlk);
            UTLT_Assert(status == STATUS_OK, goto freeBuf, "PfcpParseMessage error");

            if (pfcpMessage->header.seidP) {

                // if SEID presence
                if (!pfcpMessage->header.seid) {
                    // without SEID
                    if (pfcpMessage->header.type == PFCP_SESSION_ESTABLISHMENT_REQUEST) {
                        session = UpfSessionAddByMessage(pfcpMessage);
                    } else {
                        UTLT_Assert(0, goto freeBuf,
                                    "no SEID but not SESSION ESTABLISHMENT");
                    }
                } else {
                    // with SEID
                    session = UpfSessionFindBySeid(pfcpMessage->header.seid);
                }

                UTLT_Assert(session, goto freeBuf,
                            "do not find / establish session");

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

            switch (pfcpMessage->header.type) {
            case PFCP_HEARTBEAT_REQUEST:
                UTLT_Info("[PFCP] Handle PFCP heartbeat request");
                UpfN4HandleHeartbeatRequest(xact, &pfcpMessage->heartbeatRequest);
                break;
            case PFCP_HEARTBEAT_RESPONSE:
                UTLT_Info("[PFCP] Handle PFCP heartbeat response");
                UpfN4HandleHeartbeatResponse(xact, &pfcpMessage->heartbeatResponse);
                break;
            case PFCP_ASSOCIATION_SETUP_REQUEST:
                UTLT_Info("[PFCP] Handle PFCP association setup request");
                UpfN4HandleAssociationSetupRequest(xact,
                                                   &pfcpMessage->pFCPAssociationSetupRequest);
                break;
            case PFCP_ASSOCIATION_UPDATE_REQUEST:
                UTLT_Info("[PFCP] Handle PFCP association update request");
                UpfN4HandleAssociationUpdateRequest(xact,
                                                    &pfcpMessage->pFCPAssociationUpdateRequest);
                break;
            case PFCP_ASSOCIATION_RELEASE_RESPONSE:
                UTLT_Info("[PFCP] Handle PFCP association release response");
                UpfN4HandleAssociationReleaseRequest(xact,
                                                     &pfcpMessage->pFCPAssociationReleaseRequest);
                break;
            case PFCP_SESSION_ESTABLISHMENT_REQUEST:
                // DumpUpfSession();
                UTLT_Info("[PFCP] Handle PFCP session establishment request");
                UpfN4HandleSessionEstablishmentRequest(session, xact,
                                                       &pfcpMessage->pFCPSessionEstablishmentRequest);
                // DumpUpfSession();
                break;
            case PFCP_SESSION_MODIFICATION_REQUEST:
                UTLT_Info("[PFCP] Handle PFCP session modification request");
                UpfN4HandleSessionModificationRequest(session, xact,
                                                      &pfcpMessage->pFCPSessionModificationRequest);
                break;
            case PFCP_SESSION_DELETION_REQUEST:
                UTLT_Info("[PFCP] Handle PFCP session deletion request");
                UpfN4HandleSessionDeletionRequest(session, xact,
                                                  &pfcpMessage->pFCPSessionDeletionRequest);
                break;
            case PFCP_SESSION_REPORT_RESPONSE:
                UTLT_Info("[PFCP] Handle PFCP session report response");
                UpfN4HandleSessionReportResponse(session, xact,
                                                 &pfcpMessage->pFCPSessionReportResponse);
                break;
            default:
                UTLT_Error("No implement pfcp type: %d", pfcpMessage->header.type);
            }
            freeBuf:
                PfcpStructFree(pfcpMessage);
                BufblkFree(bufBlk);
            break;
        }
        case UPF_EVENT_N4_T3_RESPONSE:
        case UPF_EVENT_N4_T3_HOLDING: {
            uint8_t type;
            PfcpXactTimeout((uint32_t) event->arg0,
                            (UpfEvent)event->type, &type);
            break;
        }
        default: {
            UTLT_Error("No handler for event type: %d", event->type);
            break;
        }
    }
}

char* multiplyByDash(int num) {
    char* result = malloc((num * 4 + 1) * sizeof(char));
    strcpy(result, "");
    for (int i = 0; i < num; i++) {
        strcat(result, "---");
    }
    return result;
}


int MyTlvParseMessage(void * msg, IeDescription * msgDes, void * buff, int buffLen,int dashTime) {
    // UTLT_Info("MyTlvParseMessage");
    int dbf = 1; // debug flag
    int msgPivot = 0; // msg (struct) offset
    //void *root = buff;
    int buffOffset = 0; // buff offset
    int idx = 0 ;

    char* dash = multiplyByDash(dashTime);

    UTLT_Info("%s msgDes->numToParse: %d", dash,msgDes->numToParse);
    // UTLT_Info("%s %s", GetStringFromTable(msgDes->next[idx]),dash);


    for (idx = 0; idx < msgDes->numToParse; ++idx) {
        UTLT_Info("%s %s", GetStringFromTable(msgDes->next[idx]),dash);
        // if (dbf) { 
        //     UTLT_Info("%s idx: %d", dash ,idx);
        //     if (ieDescriptionTable[msgDes->next[idx]].msgType == 57) {
        //         UTLT_Warning("%s Get F-SEID",dash);
        //     } 
        // }
        IeDescription *ieDes = &ieDescriptionTable[msgDes->next[idx]];
        uint16_t type;
        uint16_t length;
        memcpy(&type, buff + buffOffset, sizeof(uint16_t));
        memcpy(&length, buff + buffOffset + sizeof(uint16_t), sizeof(uint16_t));

        type = ntohs(type);
        length = ntohs(length);

        if (type != ieDes->msgType) {
            if (dbf) { 
                UTLT_Warning("%s ieDes->msgType: %d not present, type: %d", dash ,ieDes->msgType, type); 
                // UTLT_Warning("%s ieDes->msgLen: %d", dash ,ieDes->msgLen);
            }
            // not present
            (*(unsigned long*)(msg + msgPivot)) = 0; // presence
            msgPivot += ieDes->msgLen;
            // UTLT_Info("%s msgPivot: %d", dash ,msgPivot);
            continue;
        }

        if (ieDes->isTlvObj) {
            //if (dbf) { UTLT_Info("%s is TLV: %p",dash ,msg+msgPivot); }
            ((TlvOctet*)(msg+msgPivot))->presence = 1;
            ((TlvOctet*)(msg+msgPivot))->type = type;
            void *newBuf = UTLT_Malloc(length);
            memcpy(newBuf, buff + buffOffset + 2*sizeof(uint16_t), length);
            ((TlvOctet*)(msg+msgPivot))->len = length;
            ((TlvOctet*)(msg+msgPivot))->value = newBuf;

            UTLT_Info("%s type: %d, len: %d", dash ,type, length);
            UTLT_Info("%s buffOffset: %d + %d ", dash,buffOffset,sizeof(uint16_t)*2 + length);
            buffOffset += sizeof(uint16_t)*2 + length;
            UTLT_Info("%s msgPivot: %d + %d ", dash ,msgPivot ,sizeof(TlvOctet));
            msgPivot += sizeof(TlvOctet);
            
            continue;
        } else {
            // UpdateFar is here
            if (dbf) { UTLT_Info("%s not TLV, desTB mstype: %d",dash ,ieDes->msgType); }
            // recursive
            *((unsigned long*)(msg+msgPivot)) = 1; // presence
            
            MyTlvParseMessage(msg+msgPivot+sizeof(unsigned long), ieDes, buff + buffOffset + sizeof(uint16_t)*2, buffLen - buffOffset,dashTime+1);
            //int size = _TlvParseMessage(msg+msgPivot, ieDes, buff + buffOffset, buffLen - buffOffset);
            UTLT_Info("%s type: %d, len: %d", dash ,type, length);
            UTLT_Info("%s buffOffset: %d + %d ", dash,buffOffset,sizeof(uint16_t)*2 + length);
            buffOffset += length + sizeof(uint16_t)*2;
            UTLT_Info("%s msgPivot: %d + %d ", dash ,msgPivot ,ieDes->msgLen);
            msgPivot += ieDes->msgLen;

        }
    }
    return buffOffset;
}
