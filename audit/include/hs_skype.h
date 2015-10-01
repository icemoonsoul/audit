#ifndef _HS_SKYPE_H_
#define _HS_SKYPE_H_

#include "hs_core.h"
#include "hs_consts.h"
#include "hs_dfi.h"

#define DPI_SKYPE_BEGIN_SCAN 	8
#define DPI_SKYPE_END_SCAN   	32

typedef struct skype_stat {
	UINT16 protocol;
	UINT16 port;
    UINT16 pkt_skypelen_c2s[HS_DFI_STAT_PACKET_NUM];
    UINT16 pkt_skypelen_s2c[HS_DFI_STAT_PACKET_NUM];
} SKYPE_STAT_S;

typedef struct skype_conn {
	SKYPE_STAT_S stStat;
    UINT16 pkt_skypenum_c2s;
    UINT16 pkt_skypenum_s2c;
} SKYPE_CONN_S;

INT32 HS_SKYPE_Init(void);

void HS_SKYPE_ConnDestroy(SKYPE_CONN_S *pstConn);

#endif
