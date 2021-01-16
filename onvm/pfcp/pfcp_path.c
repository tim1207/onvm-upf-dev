#define TRACE_MODULE _pfcp_path

#include <errno.h>

#include "onvm_output.h"

#include "utlt_debug.h"
#include "utlt_3gppTypes.h"
#include "utlt_network.h"
#include "utlt_buff.h"

#include "pfcp_node.h"

#include "pfcp_path.h"

Status PfcpServer(SockNode *snode, SockHandler handler) {
    Status status;

    UTLT_Assert(snode, return STATUS_ERROR, "socket node error");

    // TODO: config - check if snode->ip is already set when parsing config
    snode->sock = UdpServerCreate(AF_INET, snode->ip, 8805);
    status = SockRegister(snode->sock, handler, NULL);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR, "Handler register error");

    UTLT_Trace("PfcpServer() [%s]:%d\n", GetIP(&snode->sock->localAddr), 8805);

    return STATUS_OK;
}

Status PfcpServerList(ListHead *list, SockHandler handler, int epfd) {
    Status status;
    SockNode *node, *nextNode = NULL;

    UTLT_Assert(list, return STATUS_ERROR, "Server list error");
    UTLT_Assert(handler, return STATUS_ERROR, "handler error");

    ListForEachSafe(node, nextNode, list) {
        node->sock = SocketAlloc();
        node->sock->localAddr._family = AF_INET;
        status = UdpSockSetAddr(&node->sock->localAddr, AF_INET, node->ip, 8805);
        UTLT_Assert(status == STATUS_OK, return STATUS_ERROR, "Unable to set node->ip");
	UTLT_Info("[Vivek] Create server [%s]:%d\n",
			GetIP(&node->sock->localAddr), GetPort(&node->sock->localAddr));
    }

    return STATUS_OK;
}

Sock *PfcpLocalSockFirst(ListHead *list) {
    SockNode *node, *nextNode = NULL;
    Sock *sock = NULL;

    UTLT_Assert(list, return NULL, "list error");

    ListForEachSafe(node, nextNode, list) {
        sock = node->sock;
        if (sock) {
            return sock;
        }
    }

    return NULL;
}

SockAddr *PfcpLocalAddrFirst(ListHead *list) {
    SockNode *node, *nextNode = NULL;
    SockAddr *addr = NULL;

    UTLT_Assert(list, return NULL, "list error");

    ListForEachSafe(node, nextNode, list) {
        addr = &node->sock->localAddr;
        if (addr) {
            return addr;
        }
    }

    return NULL;
}

Status PfcpSend(PfcpNode *node, Bufblk *bufBlk) {
    return OnvmSend(bufBlk->buf, 3, bufBlk->len);
#if 0
    Sock *sock = NULL;
    SockAddr *addr = NULL;

    UTLT_Assert(node, return STATUS_ERROR, "No PfcpNode");
    UTLT_Assert(bufBlk, return STATUS_ERROR, "No Bufblk");
    sock = node->sock;
    UTLT_Assert(sock, return STATUS_ERROR, "No sock of node");

    /* New Interface */
    addr = &(sock->remoteAddr);
    UTLT_Assert(addr, return STATUS_ERROR, "remote addr error");
    UTLT_Assert(bufBlk, , "buff NULL");
    UTLT_Assert(bufBlk->buf, , "buff buff NULL");

    Status status = SockSendTo(sock, bufBlk->buf, bufBlk->len);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
            "Sent [%s]:%d failed(%d:%s)", GetIP(addr), GetPort(addr), errno, strerror(errno));

    return STATUS_OK;
#endif
}


