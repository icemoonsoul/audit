#ifndef _HS_PLUGIN_H_
#define _HS_PLUGIN_H_

#if MODE == USERSPACE
#include "hs_list.h"
#elif MODE == KERNELSPACE
#include <linux/list.h>
#endif

#include "hs_consts.h"
#include "hs_types.h"
#include "hs.h"
#include "hs_core.h"
#include "hs_alg.h"

#define TUPLE5_INT_NUM	(sizeof(struct tuple5)/sizeof(INT32))

void HS_Plugin_Init(void);

void HS_Plugin_Exit(void);

#endif
