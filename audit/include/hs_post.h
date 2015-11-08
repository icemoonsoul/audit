#ifndef _HS_POST_H_
#define _HS_POST_H_
#include <stdio.h>
#include "hs.h"
#include "hs_types.h"
#include "hs_list.h"
#include "hs_core.h"

#define MAX_POST_PAYLOAD_LEN        1500
#define MAX_POST_CNT_LEN            1048576
#define MAX_POST_SCAN_NUM           64

typedef enum post_state {
    POST_STATE_INITIAL = 0,     // ��ʼ״̬��׼������POST�����ģ�������Ҳû�л�������
    POST_STATE_HEAD_END,
    POST_STATE_HEAD_TRUNCATE,   //  head���ضϣ���Ҫ�����հ���
    POST_STATE_BODY_END,        // �������л������ݣ����Ǳ���post�������������־�󼴿��û�POST_STATE_INITIAL       
    POST_STATE_BODY_TRUNCATE,   // �������л������ݣ���Ҫ�����հ�
    POST_STATE_ERROR,           // ���̳���ĳ�����ı�����������POST���ʧЧ
    POST_STATE_MAX
} POST_STATE_E;

typedef struct post_node {
    LIST_HEAD_S node;
    UINT32 uLen;
    UCHAR pucData[0];
} POST_NODE_S;

static inline POST_NODE_S *AllocPostNode(UCHAR *pucData, UINT32 uLen)
{
    POST_NODE_S *pstNode = hs_malloc(sizeof(POST_NODE_S) + uLen);
    if (pstNode == NULL) {
        return NULL;
    }

    INIT_LIST_HEAD(&pstNode->node);
    pstNode->uLen = uLen;
    memcpy(pstNode->pucData, pucData, uLen);

    return pstNode;
}

typedef struct post_info {
    FILE *fp;
    INT32 direct;
    UINT32 uCntLen;
    CHAR *pcHost;
    CHAR *pcUri;
    UCHAR *pucCnt;     // ΪContent������ڴ���
    UCHAR *pucCntCurr;  // ָ�����Content�ڴ��ָ��
    POST_STATE_E enState;
    UINT32 uIdx;        // ָ���������ĸ��ؼ���
} POST_INFO_S;

static inline void InitPostInfo(POST_INFO_S *pstPost)
{
    memset(pstPost, 0 ,sizeof(POST_INFO_S));
}

static inline void DestroyPostInfo(POST_INFO_S *pstPost)
{
    if (pstPost->pucCnt != NULL) {
        hs_free(pstPost->pucCnt);
        pstPost->pucCnt = pstPost->pucCntCurr = NULL;
    }

    if (pstPost->pcUri != NULL) {
        hs_free(pstPost->pcUri);
        pstPost->pcUri = NULL;
    }

    if (pstPost->pcHost != NULL) {
        hs_free(pstPost->pcHost);
        pstPost->pcHost = NULL;
    }
}

INT32 HS_POST_Init(void);

#endif
