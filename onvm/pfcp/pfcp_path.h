#ifndef __PFCP_PATH_H__
#define __PFCP_PATH_H__

#include "utlt_debug.h"
#include "utlt_3gppTypes.h"
#include "utlt_network.h"
#include "utlt_buff.h"

#include "pfcp_node.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

Status PfcpServerList(ListHead *list, SockHandler handler, int epfd);
Sock *PfcpLocalSockFirst(ListHead *list);
SockAddr *PfcpLocalAddrFirst(ListHead *list);
Status PfcpSend(PfcpNode *node, Bufblk *bufBlk);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
