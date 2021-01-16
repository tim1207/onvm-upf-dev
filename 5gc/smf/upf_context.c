#define TRACE_MODULE _upf_context

#include "upf_context.h"

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <netinet/in.h>
#include <net/if.h>

#include "utlt_debug.h"
#include "utlt_pool.h"
#include "utlt_index.h"
#include "utlt_hash.h"
#include "utlt_network.h"
#include "utlt_netheader.h"

#include "pfcp_message.h"
#include "pfcp_types.h"
#include "pfcp_xact.h"

#include "up/up_match.h"

#include "updk/env.h"
#include "updk/init.h"
#include "updk/rule.h"
#include "updk/rule_pdr.h"
#include "updk/rule_far.h"

#define MAX_NUM_OF_SUBNET       16

IndexDeclare(upfSessionPool, UpfSession, MAX_POOL_OF_SESS);

static UpfContext self;
static _Bool upfContextInitialized = 0;

UpfContext *Self() {
    return &self;
}

Status UpfContextInit() {
    UTLT_Assert(upfContextInitialized == 0, return STATUS_ERROR,
                "UPF context has been initialized!");

    memset(&self, 0, sizeof(UpfContext));

    // TODO : Add GTPv1 init here
    self.envParams = AllocEnvParams();
    UTLT_Assert(self.envParams, return STATUS_ERROR,
        "EnvParams alloc failed");

    self.upSock.fd = -1;
    SockSetEpollMode(&self.upSock, EPOLLIN);

    // TODO : Add PFCP init here
    ListHeadInit(&self.pfcpIPList);

    ListHeadInit(&self.ranS1uList);
    ListHeadInit(&self.upfN4List);
    ListHeadInit(&self.dnnList);

    self.recoveryTime = htonl(time((time_t *)NULL));

    // Set Default Value
    self.gtpDevNamePrefix = "upfgtp";
    // defined in utlt_3gpptypes instead of GTP_V1_PORT defined in GTP_PATH;
    self.gtpv1Port = GTPV1_U_UDP_PORT;
    self.pfcpPort = PFCP_UDP_PORT;
    strcpy(self.envParams->virtualDevice->deviceID, self.gtpDevNamePrefix);

    // Init Resource
    IndexInit(&upfSessionPool, MAX_POOL_OF_SESS);

    PfcpNodeInit(); // init pfcp node for upfN4List (it will used pfcp node)
    TimerListInit(&self.timerServiceList);

    self.sessionHash = HashMake();
    self.bufPacketHash = HashMake();

    upfContextInitialized = 1;

    return STATUS_OK;
}

// TODO : Need to Remove List Members iterativelyatively
Status UpfContextTerminate() {
    UTLT_Assert(upfContextInitialized == 1, return STATUS_ERROR,
                "UPF context has been terminated!");

    Status status = STATUS_OK;

    int ret = pthread_spin_destroy(&self.buffLock);
    UTLT_Assert(ret == 0, , "buffLock cannot destroy: %s", strerror(ret));
    UTLT_Assert(self.bufPacketHash, , "Buffer Hash Table missing?!");
    HashDestroy(self.bufPacketHash);

    UTLT_Assert(self.sessionHash, , "Session Hash Table missing?!");
    HashDestroy(self.sessionHash);

    // Terminate resource
    IndexTerminate(&upfSessionPool);

    PfcpRemoveAllNodes(&self.upfN4List);
    PfcpNodeTerminate();

    // TODO: remove gtpv1TunnelList, ranS1uList, upfN4LIst, dnnList,
    // pdrList, farList, qerList, urrLIist
    SockNodeListFree(&self.pfcpIPList);
    // SockNodeListFree(&self.pfcpIPv6List);
    FreeVirtualDevice(self.envParams->virtualDevice);

    upfContextInitialized = 0;

    return status;
}

HashIndex *UpfSessionFirst() {
    UTLT_Assert(self.sessionHash, return NULL, "");
    return HashFirst(self.sessionHash);
}

HashIndex *UpfSessionNext(HashIndex *hashIdx) {
    UTLT_Assert(hashIdx, return NULL, "");
    return HashNext(hashIdx);
}

UpfSession *UpfSessionThis(HashIndex *hashIdx) {
    UTLT_Assert(hashIdx, return NULL, "");
    return (UpfSession *)HashThisVal(hashIdx);
}

void SessionHashKeygen(uint8_t *out, int *outLen, uint8_t *imsi,
                       int imsiLen, uint8_t *dnn) {
    memcpy(out, imsi, imsiLen);
    strncpy((char *)(out + imsiLen), (char*)dnn, MAX_DNN_LEN + 1);
    *outLen = imsiLen + strlen((char *)(out + imsiLen));

    return;
}

UpfSession *UpfSessionAdd(PfcpUeIpAddr *ueIp, uint8_t *dnn,
                          uint8_t pdnType) {
    UpfSession *session = NULL;

    IndexAlloc(&upfSessionPool, session);
    UTLT_Assert(session, return NULL, "session alloc error");

    //session->gtpNode = NULL;

    if (self.pfcpAddr) {
        session->upfSeid =
          ((uint64_t)self.pfcpAddr->s4.sin_addr.s_addr << 32)
          | session->index;
    } else if (self.pfcpAddr6) {
        uint32_t *ptr =
          (uint32_t *)self.pfcpAddr6->s6.sin6_addr.s6_addr;
        session->upfSeid =
          (((uint64_t)(*ptr)) << 32) | session->index;
        // TODO: check if correct
    }
    session->upfSeid = htobe64(session->upfSeid);
    //UTLT_Info()
    session->upfSeid = 0; // TODO: check why

    /* IMSI DNN Hash */
    /* DNN */
    strncpy((char*)session->pdn.dnn, (char*)dnn, MAX_DNN_LEN + 1);

    ListHeadInit(&session->pdrIdList);
    ListHeadInit(&session->pdrList);
    ListHeadInit(&session->farList);
    ListHeadInit(&session->qerList);
    ListHeadInit(&session->barList);
    ListHeadInit(&session->urrList);

    session->pdn.paa.pdnType = pdnType;
    if (pdnType == PFCP_PDN_TYPE_IPV4) {
        session->ueIpv4.addr4 = ueIp->addr4;
        //session->pdn.paa.addr4 = ueIp->addr4;
    } else if (pdnType == PFCP_PDN_TYPE_IPV6) {
        session->ueIpv6.addr6 = ueIp->addr6;
        //session->pdn.paa.addr6 = ueIp->addr6;
    } else if (pdnType == PFCP_PDN_TYPE_IPV4V6) {
        // TODO
        // session->ueIpv4 = UpfUeIPAlloc(AF_INET, dnn);
        // UTLT_Assert(session->ueIpv4,
        //   UpfSessionRemove(session); return NULL,
        //   "Cannot allocate IPv4");

        // session->ueIpv6 = UpfUeIPAlloc(AF_INET6, dnn);
        // UTLT_Assert(session->ueIpv6,
        //   UpfSessionRemove(session); return NULL,
        //   "Cannot allocate IPv6");

        // session->pdn.paa.dualStack.addr4 = session->ueIpv4->addr4;
        // session->pdn.paa.dualStack.addr6 = session->ueIpv6->addr6;
    } else {
        UTLT_Assert(0, return NULL, "UnSupported PDN Type(%d)", pdnType);
    }

    /* Generate Hash Key: IP + DNN */
    if (pdnType == PFCP_PDN_TYPE_IPV4) {
        SessionHashKeygen(session->hashKey,
                          &session->hashKeylen,
                          (uint8_t *)&session->ueIpv4.addr4, 4, dnn);
    } else {
        SessionHashKeygen(session->hashKey,
                          &session->hashKeylen,
                          (uint8_t *)&session->ueIpv6.addr6,
                          IPV6_LEN, dnn);
    }

    HashSet(self.sessionHash, session->hashKey,
            session->hashKeylen, session);

    return session;
}

Status UpfSessionRemove(UpfSession *session) {
    UTLT_Assert(self.sessionHash, return STATUS_ERROR,
                "sessionHash error");
    UTLT_Assert(session, return STATUS_ERROR, "session error");

    HashSet(self.sessionHash, session->hashKey,
            session->hashKeylen, NULL);

    // if (session->ueIpv4) {
    //     UpfUeIPFree(session->ueIpv4);
    // }
    // if (session->ueIpv6) {
    //     UpfUeIPFree(session->ueIpv6);
    // }

    // PDR_Thread_Safe(
    //     RuleListDeletionAndFreeWithGTPv1Tunnel(PDR, pdr, session);
    // );

    // FAR_Thread_Safe(
    //     RuleListDeletionAndFreeWithGTPv1Tunnel(FAR, far, session);
    // );


    // RuleListDeletionAndFreeWithGTPv1Tunnel(PDR, pdr, session);
    // RuleListDeletionAndFreeWithGTPv1Tunnel(FAR, far, session);
    /* TODO: Not support yet
    QER_Thread_Safe(
        RuleListDeletionAndFreeWithGTPv1Tunnel(QER, qer, session);
    );

    BAR_Thread_Safe(
        RuleListDeletionAndFreeWithGTPv1Tunnel(BAR, bar, session);
    );

    URR_Thread_Safe(
        RuleListDeletionAndFreeWithGTPv1Tunnel(URR, urr, session);
    );
    */

    IndexFree(&upfSessionPool, session);

    return STATUS_OK;
}

Status UpfSessionRemoveAll() {
    HashIndex *hashIdx = NULL;
    UpfSession *session = NULL;

    for (hashIdx = UpfSessionFirst(); hashIdx;
         hashIdx = UpfSessionNext(hashIdx)) {
        session = UpfSessionThis(hashIdx);
        UpfSessionRemove(session);
    }

    return STATUS_OK;
}

UpfSession *UpfSessionFind(uint32_t idx) {
    //UTLT_Assert(idx, return NULL, "index error");
    return IndexFind(&upfSessionPool, idx);
}

UpfSession *UpfSessionFindBySeid(uint64_t seid) {
    return UpfSessionFind((seid-1) & 0xFFFFFFFF);
}

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

    session = UpfSessionAdd((PfcpUeIpAddr *)
                &request->createPDR[0].pDI.uEIPAddress.value,
                request->createPDR[0].pDI.networkInstance.value,
                ((int8_t *)request->pDNType.value)[0]);
    UTLT_Assert(session, return NULL, "session add error");

    session->smfSeid = *(uint64_t*)request->cPFSEID.value;
    session->upfSeid = session->index+1;
    UTLT_Trace("UPF Establishment UPF SEID: %lu", session->upfSeid);

    return session;
}

