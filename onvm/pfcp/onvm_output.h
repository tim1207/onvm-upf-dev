#ifndef __ONVM_OUTPUT_H__
#define __ONVM_OUTPUT_H__

#include "onvm_common.h"
#include "utlt_buff.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

void   OnvmSetNfContext(struct onvm_nf_local_ctx *nf_ctx);
Status OnvmSend(char *buff, int service_id, int buff_length);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
