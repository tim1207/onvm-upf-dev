#define TRACE_MODULE _n4_pfcp_build

#include <stdint.h>
#include <endian.h>
#include <string.h>
#include <arpa/inet.h>

#include "5gc/upf.h"
#if 0
#include "upf_context.h"
#include "pfcp_convert.h"
#include "updk/env.h"
#endif
#include "utlt_buff.h"
#include "pfcp_message.h"

#include "n4_pfcp_build.h"
#if 0
Status UpfN4BuildAssociationSetupResponse(Bufblk **bufBlkPtr, uint8_t type) {
    Status status;
    PfcpMessage pfcpMessage;
    PFCPAssociationSetupResponse *response = NULL;
    uint8_t cause;
    uint16_t upFunctionFeature;

    response = &pfcpMessage.pFCPAssociationSetupResponse;
    memset(&pfcpMessage, 0, sizeof(PfcpMessage));
    pfcpMessage.pFCPAssociationSetupResponse.presence = 1;

    /* cause */
    cause = PFCP_CAUSE_REQUEST_ACCEPTED;
    response->cause.presence = 1;
    response->cause.value = &cause;
    response->cause.len = 1;

    pfcpMessage.header.type = type;
    status = PfcpBuildMessage(bufBlkPtr, &pfcpMessage);
    UTLT_Assert(*bufBlkPtr, , "buff NULL");
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR, "PFCP build error");

    UTLT_Debug("PFCP association session setup response built!");
    return STATUS_OK;
}
#endif
