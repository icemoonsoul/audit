#ifndef _HS_CNT_H_
#define _HS_CNT_H_

UINT32 CONTENT_Scan(DFA_S **pstGraphList, struct graph_appid_list *pstAppIdList, UINT32 uGraphNum, HS_PKT_DETAIL_S *pstDetail);

UINT32 HS_CONTENT_Scan(HS_DATA_S *pstDpi, HS_PKT_DETAIL_S *pstDetail);

UINT32 HS_CheckAppPriority(BOOL bScanPktLen, DFA_APPID_S *pstDfaAppId, UINT32 *puId, UINT32 uIdNum, \
        HS_PKT_DETAIL_S *pstDetail);

INT32 HS_CONTENT_Init(void);

#endif
