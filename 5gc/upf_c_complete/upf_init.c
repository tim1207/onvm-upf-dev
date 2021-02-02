#include "upf_init.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>

#include "utlt_lib.h"
#include "utlt_debug.h"
#include "utlt_buff.h"
#include "utlt_thread.h"
#include "utlt_timer.h"
#include "utlt_network.h"
#include "upf_context.h"
#include "upf_config.h"
#include "n4_onvm_pfcp_path.h"
#include "pfcp_xact.h"

#include "updk/env.h"
#include "updk/init.h"


static Status ConfigHandle(void *data);

static Status PfcpInit(void *data);
static Status PfcpTerm(void *data);

static char configFilePath[MAX_FILE_PATH_STRLEN] = "./config/upfcfg.yaml";

UpfOps UpfOpsList[] = {
    {
        .name = "Library - Bufblk Pool",
        .init = BufblkPoolInit,
        .initData = NULL,
        .term = BufblkPoolFinal,
        .termData = NULL,
    },
    {
        .name = "Library - Timer Pool",
        .init = TimerPoolInit,
        .initData = NULL,
        .term = TimerFinal,
        .termData = NULL,
    },
    {
        .name = "Library - Socket Pool",
        .init = SockPoolInit,
        .initData = NULL,
        .term = SockPoolFinal,
        .termData = NULL,
    },
    {
        .name = "UPF - Context",
        .init = UpfContextInit,
        .initData = NULL,
        .term = UpfContextTerminate,
        .termData = NULL,
    },
    {
        .name = "UPF - Config Handle",
        .init = ConfigHandle,
        .initData = NULL,
        .term = NULL,
        .termData = NULL,
    },
    {
        .name = "UPF - PFCP",
        .init = PfcpInit,
        .initData = NULL,
        .term = PfcpTerm,
        .termData = NULL,
    },
};

Status UpfSetConfigPath(char *path) {
    strcpy(configFilePath, path);
    return STATUS_OK;
}

Status UpfInit() {
    Status status = STATUS_OK;

#if 0
    UTLT_Assert(GetAbsPath(configFilePath) == STATUS_OK, 
        return STATUS_ERROR, "Invalid config path: %s", configFilePath);
#endif
    UTLT_Info("Config: %s", configFilePath);

    for (int i = 0; i < sizeof(UpfOpsList) / sizeof(UpfOps); i++) {
        if (UpfOpsList[i].init) {
            status = UpfOpsList[i].init(UpfOpsList[i].initData);
            UTLT_Assert(status == STATUS_OK, status |= STATUS_ERROR; break,
                "%s error when UPF initializes", UpfOpsList[i].name);
            
            UTLT_Trace("%s is finished in UPF initialization", UpfOpsList[i].name);
        }
    }
    return status;
}

Status UpfTerm() {
    Status status = STATUS_OK;
    for (int i = (int)(sizeof(UpfOpsList) / sizeof(UpfOps)) - 1; i >= 0 ; i--) {
        if (UpfOpsList[i].term) {
            status = UpfOpsList[i].term(UpfOpsList[i].termData);
            UTLT_Assert(status == STATUS_OK, status |= STATUS_ERROR,
                "%s error when UPF terminates", UpfOpsList[i].name);

            UTLT_Trace("%s is finished in UPF termination", UpfOpsList[i].name);
        }
    }
    
    return status;
}

static Status ConfigHandle(void *data) {
    UTLT_Assert(UpfLoadConfigFile(configFilePath) == STATUS_OK,
        return STATUS_ERROR, "");

    UTLT_Assert(UpfConfigParse() == STATUS_OK,
        return STATUS_ERROR, "");

    return STATUS_OK;
}

static Status PfcpInit(void *data) {
    Status status = STATUS_OK;
    UTLT_Assert(PfcpServerInit() == STATUS_OK,
        status |= STATUS_ERROR, "");

    // init pfcp xact context
    UTLT_Assert(PfcpXactInit(&Self()->timerServiceList,
                    0, 0) == STATUS_OK,
        status |= STATUS_ERROR, "");

    return status;
}

static Status PfcpTerm(void *data) {
    Status status = STATUS_OK;
    UTLT_Assert(PfcpXactTerminate() == STATUS_OK,
        status |= STATUS_ERROR, "");

    UTLT_Assert(PfcpServerTerminate() == STATUS_OK,
        status |= STATUS_ERROR, "");

    return status;
}
