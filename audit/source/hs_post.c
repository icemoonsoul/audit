#include "hs_post.h"
#include "hs_http.h"

#define MAX_POST_INDICATOR_LEN      16

struct post_indicator {
    char begin[MAX_POST_INDICATOR_LEN];
    char end[MAX_POST_INDICATOR_LEN];
};

struct post_indicator g_PostIndicator[] = {
        {"content=", "&"},
        {"con=", "&"},
        {"c=", "&"},
    };

FILE *g_pstPostLog = NULL;
static HS_time_t post_ts;
UINT32 post_ts_delta = 60;

unsigned int g_uPostIndicatorNum = sizeof(g_PostIndicator)/sizeof(struct post_indicator);

extern UCHAR *DPI_StrnStr(UCHAR *pu8Src, UCHAR *pu8Sub, UINT32 u32SrcLen);
INT32 POST_Error(HS_CTX_S *pstCtx, HS_PKT_DETAIL_S *pstDetail);
INT32 POST_BodyEnd(HS_CTX_S *pstCtx, HS_PKT_DETAIL_S *pstDetail);

void CntCopy(POST_INFO_S *pstPost, UCHAR *pucData, UINT32 uNewLen)
{
    memcpy(pstPost->pucCntCurr, pucData, uNewLen);
    pstPost->pucCntCurr += uNewLen;
}

// header结尾的地方有两个回车换行
UCHAR* HttpHeaderEnd(const CHAR *header, UINT32 len)
{
    const char *lf, *nxtlf, *end;
    const char *buf_end;
   
    end = NULL;
    buf_end = header + len;
    lf =  memchr(header, '\n', len);
    if (lf == NULL)
        return NULL;
    lf++; /* next charater */
    nxtlf = memchr(lf, '\n', buf_end - lf);
    while (nxtlf != NULL) {
        if (nxtlf-lf < 2) {
            end = nxtlf;
            break;
        }
        nxtlf++;
        lf = nxtlf;
        nxtlf = memchr(nxtlf, '\n', buf_end - nxtlf);
    }

    return (unsigned char *)end;
}

#if 0
int POST_GenFilePath(CHAR *pcPath, UINT32 *uLen)
{
    strcpy(pcPath, "./post.txt");
}

INT32 InsertContent(POST_INFO_S *pstPost, UCHAR *pucData, UINT32 uLen)
{
    POST_NODE_S *pstNode = AllocPostNode(pucData, uLen);
    if (pstNode == NULL) {
        return HS_ERR;
    }

    //list_add_tail(&pstNode->node, &pstPost->cnt_head);

    return HS_OK;
}
#endif

INT32 GetPostContent(POST_INFO_S *pstPost, UINT32 *puPostBegin, UINT32 *puPostEnd)
{
    UCHAR *pucBegin, *pucEnd;
    UINT32 idx;
    UCHAR *pucData = pstPost->pucCnt;
    UINT32 uLen = pstPost->uCntLen;
    
    for (idx = 0; idx < g_uPostIndicatorNum; idx++) {
        pucBegin = DPI_StrnStr(pucData, g_PostIndicator[idx].begin, uLen);
        if (pucBegin == NULL) {
            continue;
        }
        
        pucEnd = DPI_StrnStr(pucBegin + strlen(g_PostIndicator[idx].begin), g_PostIndicator[idx].end, uLen - (pucBegin - pucData));
        if (pucEnd != NULL) {
            *puPostBegin = pucBegin - pucData + strlen(g_PostIndicator[idx].begin);
            *puPostEnd = pucEnd - pucData;
            return HS_OK;
        } 
    }

    return HS_ERR;
}



// 没有该字段不算错，有该字段但是不符合要求，算错
INT32 GetContentLength(UCHAR *pucData, UINT32 uLen, UINT32 *puCntLen)
{
    UCHAR *pucPos;
    
    pucPos = DPI_StrnStr(pucData, "Content-Length:", uLen);
    if (pucPos == NULL) {
        *puCntLen = 0;
        return HS_OK;
    }

    *puCntLen = atoi(pucPos + strlen("Content-Length:"));
    if (*puCntLen == 0 || *puCntLen > MAX_POST_CNT_LEN) {
        return HS_ERR;
    }
    
    return HS_OK;
}

static INT32 POST_LogUriHost(HS_CTX_S *pstCtx, HS_PKT_DETAIL_S *pstDetail)
{
    POST_INFO_S *pstPost = pstCtx->pstPost;
    HTTP_HEAD_INFO_S stHttpInfo;
    
    if (HTTP_RequestParse(&stHttpInfo, pstDetail) == HS_OK) {
        // log uri
        if (stHttpInfo.arrInfo[HTTP_FIELD_URI].pucData != NULL) {
            pstPost->pcUri = hs_malloc(stHttpInfo.arrInfo[HTTP_FIELD_URI].uLen + 1);
            if (pstPost->pcUri == NULL) {
                HS_WARN("malloc error.\n");
                pstPost->enState = POST_STATE_ERROR;
                return POST_Error(pstCtx, pstDetail);
            }

            strncpy(pstPost->pcUri, stHttpInfo.arrInfo[HTTP_FIELD_URI].pucData, stHttpInfo.arrInfo[HTTP_FIELD_URI].uLen);
            pstPost->pcUri[stHttpInfo.arrInfo[HTTP_FIELD_URI].uLen] = '\0';
        }

        // log host
        if (stHttpInfo.arrInfo[HTTP_FIELD_HOST].pucData != NULL) {
            pstPost->pcHost = hs_malloc(stHttpInfo.arrInfo[HTTP_FIELD_HOST].uLen + 1);
            if (pstPost->pcHost == NULL) {
                HS_WARN("malloc error.\n");
                pstPost->enState = POST_STATE_ERROR;
                return POST_Error(pstCtx, pstDetail);
            }

            strncpy(pstPost->pcHost, stHttpInfo.arrInfo[HTTP_FIELD_HOST].pucData, stHttpInfo.arrInfo[HTTP_FIELD_HOST].uLen);
            pstPost->pcHost[stHttpInfo.arrInfo[HTTP_FIELD_HOST].uLen] = '\0';
        }
    }
    
    return HS_OK;
}

INT32 POST_Initial(HS_CTX_S *pstCtx, HS_PKT_DETAIL_S *pstDetail)
{
    UCHAR *pucHeadEnd = NULL;
    UINT32 uCntLen = 0;     
    UINT32 uBodyLen = 0;
    POST_INFO_S *pstPost = pstCtx->pstPost;

    if (strncmp(pstDetail->data, "POST", 4) != 0) {
        return HS_OK;
    }

    pstPost->direct = pstDetail->direct;

    pucHeadEnd = HttpHeaderEnd(pstDetail->data, pstDetail->length);
    if (pucHeadEnd == NULL) {
        // 查找content length
        pstPost->enState = POST_STATE_HEAD_TRUNCATE;
        
        if (GetContentLength(pstDetail->data, pstDetail->length, &uCntLen) != HS_OK) {
            // 清理后继续收包
            pstPost->enState = POST_STATE_ERROR;
            return POST_Error(pstCtx, pstDetail);
        }

        if (uCntLen == 0) {
            // 还没有定义该域，继续收包
            return HS_OK;
        }

        pstPost->pucCnt = pstPost->pucCntCurr = hs_malloc(uCntLen);
        if (pstPost->pucCnt == NULL) {
            HS_WARN("malloc error.\n");
            pstPost->enState = POST_STATE_ERROR;
            return POST_Error(pstCtx, pstDetail);
        }
        pstPost->uCntLen = uCntLen;

        POST_LogUriHost(pstCtx, pstDetail);
    }
    
    if (GetContentLength(pstDetail->data, pstDetail->length, &uCntLen) != HS_OK) {
        // 清理后继续收包
        pstPost->enState = POST_STATE_ERROR;
        return POST_Error(pstCtx, pstDetail);
    }

    if (uCntLen == 0) {
        // 还没有定义该域，继续收包
        return HS_OK;
    }
    
    pstPost->pucCnt = pstPost->pucCntCurr = hs_malloc(uCntLen);
    if (pstPost->pucCnt == NULL) {
        HS_WARN("malloc error.\n");
        pstPost->enState = POST_STATE_ERROR;
        return POST_Error(pstCtx, pstDetail);
    }
    pstPost->uCntLen = uCntLen;

    POST_LogUriHost(pstCtx, pstDetail);

    uBodyLen = (pstDetail->data + pstDetail->length) - (pucHeadEnd + 1);

    if (uBodyLen > uCntLen) {
        // 实际载荷大于指示值，出错。
        pstPost->enState = POST_STATE_ERROR;

        return POST_Error(pstCtx, pstDetail);
    } else if (uBodyLen < uCntLen) {
        // post content truncate
        pstPost->enState = POST_STATE_BODY_TRUNCATE;
        if (uBodyLen > 0) {
            // 排除恰好就传输了post header
            memcpy(pstPost->pucCntCurr, pucHeadEnd + 1, uBodyLen);
            pstPost->pucCntCurr += uBodyLen;
        }

        return HS_OK;
    } else {
        memcpy(pstPost->pucCntCurr, pucHeadEnd + 1, uBodyLen);
        pstPost->pucCntCurr += uBodyLen;
        pstPost->enState = POST_STATE_BODY_END;

        return POST_BodyEnd(pstCtx, pstDetail);
    }
}

INT32 POST_HeadTruncate(HS_CTX_S *pstCtx, HS_PKT_DETAIL_S *pstDetail)
{
    UCHAR *pucHeadEnd = NULL;
    UINT32 uCntLen = 0;     
    UINT32 uBodyLen = 0;
    POST_INFO_S *pstPost = pstCtx->pstPost;
    
    pucHeadEnd = HttpHeaderEnd(pstDetail->data, pstDetail->length);
    if (pucHeadEnd == NULL) {
        // 已经提取了content-length:
        if (pstPost->uCntLen > 0) {
            return HS_OK;
        }
        // 只关心content-length:
        if (GetContentLength(pstDetail->data, pstDetail->length, &uCntLen) != HS_OK) {
            // 清理后继续收包
            pstPost->enState = POST_STATE_ERROR;
            return POST_Error(pstCtx, pstDetail);
        }

        if (uCntLen == 0) {
            // 还没有定义该域，继续收包
            return HS_OK;
        }
        
        return HS_OK;
    } 

    if (pstPost->uCntLen == 0) {
        if (GetContentLength(pstDetail->data, pstDetail->length, &uCntLen) != HS_OK) {
            // 清理后继续收包
            pstPost->enState = POST_STATE_ERROR;
            return POST_Error(pstCtx, pstDetail);
        }
        
        if (uCntLen == 0) {
            // 还没有定义该域，但是head已经结束了，放弃
            pstPost->enState = POST_STATE_ERROR;
            return POST_Error(pstCtx, pstDetail);
        }

        pstPost->pucCnt = pstPost->pucCntCurr = hs_malloc(uCntLen);
        if (pstPost->pucCnt == NULL) {
            HS_WARN("malloc error.\n");
            pstPost->enState = POST_STATE_ERROR;
            return POST_Error(pstCtx, pstDetail);
        }

        pstPost->uCntLen = uCntLen;
    }

    uCntLen = pstPost->uCntLen;
    
    uBodyLen = (pstDetail->data + pstDetail->length) - (pucHeadEnd + 1);

    if (uBodyLen > uCntLen) {
        // 实际载荷大于指示值，出错。
        pstPost->enState = POST_STATE_ERROR;
        return POST_Error(pstCtx, pstDetail);
    } else if (uBodyLen < uCntLen) {
        // post content truncate
        pstPost->enState = POST_STATE_BODY_TRUNCATE;
        if (uBodyLen > 0) {
            // 排除恰好就传输了post header
            CntCopy(pstPost, pucHeadEnd + 1, uBodyLen);
        }
        return HS_OK;
    } else {
        CntCopy(pstPost, pucHeadEnd + 1, uBodyLen);
        pstPost->enState = POST_STATE_BODY_END;
        return POST_BodyEnd(pstCtx, pstDetail);
    }
}

static INT32 OutputPost(const CHAR *pcLogMod, HS_time_t tv, CHAR *pcBuff)
{
    CHAR log_name[64];

START:
    if (g_pstPostLog == NULL) {
        AssignLogName(pcLogMod, tv, log_name, sizeof(log_name));
        g_pstPostLog = fopen(log_name, "w+");
        if (g_pstPostLog == NULL) {
            return HS_ERR;
        }

        post_ts = tv;
    }

    if (tv.tv_sec > post_ts.tv_sec + post_ts_delta) {
        fclose(g_pstPostLog);
        g_pstPostLog = NULL;
        goto START;
    }

    fwrite(pcBuff, 1, strlen(pcBuff), g_pstPostLog);
    fwrite("\r\n", 1, 2, g_pstPostLog);

    return HS_OK;
}

#define BUFF_PAD_UKNOWN(buff, uLen) \
    do { \
        memcpy(buff + uLen, "unknown", strlen("unknown")); \
        uLen += strlen("unknown"); \
        buff[uLen++] = '\t'; \
    } while (0)

INT32 POST_BodyEnd(HS_CTX_S *pstCtx, HS_PKT_DETAIL_S *pstDetail)
{
    CHAR buff[2048];
    UINT32 uLen = 0;
    CHAR *pcBuff = NULL;
    UINT32 uPostBegin = 0, uPostEnd = pstCtx->pstPost->uCntLen;
    UINT32 uOffset = 0;

    if (GetPostContent(pstCtx->pstPost, &uPostBegin, &uPostEnd) == HS_OK) {
        UINT32 uLen0, uLen1;
        pcBuff = hs_malloc((uPostEnd - uPostBegin) * 2 + 2);
        if (pcBuff == NULL) {
            goto ERROR;
        }

        uOffset = uPostEnd - uPostBegin + 1;

        uLen0 = HS_URL_Decode(pstCtx->pstPost->pucCnt + uPostBegin, uPostEnd - uPostBegin, pcBuff, uPostEnd - uPostBegin);
        uLen1 = HS_ICONV_Convert("GBK", "UTF8", pcBuff, uLen0, pcBuff + uOffset, uPostEnd - uPostBegin);
        if (uLen1 == -1) {
            goto ERROR;
        }

        pcBuff[uOffset + uLen1] = '\0';

        CHAR ip[16];
        HS_IpNtoa(1, pstDetail->tuple.addr.saddr, ip, 16);

        HS_PRINT("[POST]%s: %s\n", ip, pcBuff + uOffset);

        uLen += HS_MakeId(pstDetail->ts, pcBuff + uOffset, buff + uLen, sizeof(buff) - uLen);
        buff[uLen++] = '\t';

        uLen += HS_MakeTime1(pstDetail->ts, buff + uLen, sizeof(buff) - uLen);
        buff[uLen++] = '\t';

        // ServiceType
        BUFF_PAD_UKNOWN(buff, uLen);
        // HostName
        if (pstCtx->pstPost->pcUri == NULL || strlen(pstCtx->pstPost->pcUri) == 0) {
            BUFF_PAD_UKNOWN(buff, uLen);
        } else {
            memcpy(buff + uLen, pstCtx->pstPost->pcHost, strlen(pstCtx->pstPost->pcHost));
            uLen += strlen(pstCtx->pstPost->pcHost);
            buff[uLen++] = '\t';
        }
        // BBSUser
        BUFF_PAD_UKNOWN(buff, uLen);
        // Caption
        BUFF_PAD_UKNOWN(buff, uLen);
        // Content
        memcpy(buff + uLen, pcBuff + uOffset, uLen1);
        uLen += uLen1;
        buff[uLen++] = '\t';
        // URL
        if (pstCtx->pstPost->pcUri == NULL || strlen(pstCtx->pstPost->pcUri) == 0) {
            BUFF_PAD_UKNOWN(buff, uLen);
        } else {
            memcpy(buff + uLen, pstCtx->pstPost->pcUri, strlen(pstCtx->pstPost->pcUri));
            uLen += strlen(pstCtx->pstPost->pcUri);
            buff[uLen++] = '\t';
        }

        // end
        buff[uLen] = '\0';

        HS_PRINT("%s\n", buff);
        HS_WARN("%s\n", buff);
        OutputPost("gw_Post", pstDetail->ts, buff);
    }

    if (pcBuff != NULL) {
        hs_free(pcBuff);
    }
    return HS_OK;
ERROR:
    if (pcBuff != NULL) {
        hs_free(pcBuff);
    }
    return HS_ERR;
}

INT32 CheckPreCntCopy(POST_INFO_S *pstPost, UINT32 uNewLen)
{
    if (pstPost->uCntLen == 0) {
        return HS_ERR;
    }
    
    if (pstPost->pucCnt == NULL) {
        return HS_ERR;
    }

    if (pstPost->pucCntCurr < pstPost->pucCnt || pstPost->pucCntCurr > pstPost->pucCnt + pstPost->uCntLen) {
        return HS_ERR;
    }

    if (pstPost->pucCntCurr + uNewLen > pstPost->pucCnt + pstPost->uCntLen) {
        return HS_ERR;
    }

    return HS_OK;
}

INT32 IsBodyEnd(POST_INFO_S *pstPost)
{
    return pstPost->pucCntCurr == pstPost->pucCnt + pstPost->uCntLen ? HS_OK : HS_ERR;
}

INT32 POST_BodyTruncate(HS_CTX_S *pstCtx, HS_PKT_DETAIL_S *pstDetail)
{
    UINT32 uCntLen;     
    UINT32 uBodyLen = pstDetail->length;
    POST_INFO_S *pstPost = pstCtx->pstPost;

    if (CheckPreCntCopy(pstPost, uBodyLen) != HS_OK) {
        pstPost->enState = POST_STATE_ERROR;
        return POST_Error(pstCtx, pstDetail);
    }

    CntCopy(pstPost, pstDetail->data, uBodyLen);

    if (IsBodyEnd(pstPost) == HS_OK) {
        pstPost->enState = POST_STATE_BODY_END;
        return POST_BodyEnd(pstCtx, pstDetail);
    }

    return HS_OK;
}

// 重置POST_INFO_S,并恢复至POST_STATE_INITIAL
INT32 POST_Error(HS_CTX_S *pstCtx, HS_PKT_DETAIL_S *pstDetail)
{
    POST_INFO_S *pstPost = pstCtx->pstPost;

    assert(pstPost != NULL && pstPost->enState == POST_STATE_ERROR);

    DestroyPostInfo(pstPost);
    InitPostInfo(pstPost);

    return HS_OK;
}

int HS_POST_Process(HS_CTX_S *pstCtx, HS_PKT_DETAIL_S *pstDetail, void **priv)
{
    if (pstDetail->tuple.addr.dest != 80) {
        return HS_OK;
    }
    
    if (HS_PLUGIN_UNMARKED(pstCtx, HS_HOOK_POST_DPI, HS_PLUGIN_POST)) {
        HS_PLUGIN_SET_UNMARKED_ALL(pstCtx);
        HS_PLUGIN_SET_MARKED(pstCtx, HS_HOOK_POST_DPI, HS_PLUGIN_POST);
    }

    if (pstCtx->pstPost == NULL) {
        pstCtx->pstPost = hs_malloc(sizeof(POST_INFO_S));
        if (pstCtx->pstPost == NULL) {
            HS_WARN("malloc error.\n");
            return HS_ERR;
        }

        InitPostInfo(pstCtx->pstPost);
    } else {
        if (pstCtx->pstPost->direct != pstDetail->direct) {
            // 忽略回应方向报文。
            return HS_OK;
        }
    }

    switch (pstCtx->pstPost->enState) {
        case POST_STATE_INITIAL:
            POST_Initial(pstCtx, pstDetail);
            break;
        case POST_STATE_HEAD_TRUNCATE:
            POST_HeadTruncate(pstCtx, pstDetail);
            break;
        case POST_STATE_BODY_TRUNCATE:
            POST_BodyTruncate(pstCtx, pstDetail);
            break;
        case POST_STATE_HEAD_END:
        case POST_STATE_BODY_END:
        case POST_STATE_ERROR:
        default:
            DestroyPostInfo(pstCtx->pstPost);
            InitPostInfo(pstCtx->pstPost);
            return HS_ERR;
    }

    if (pstCtx->pstPost && pstCtx->pstPost->enState == POST_STATE_BODY_END) {
        DestroyPostInfo(pstCtx->pstPost);
        InitPostInfo(pstCtx->pstPost);
    }
    
    return HS_ERR;
}

void HS_POST_destroy(void **priv)
{
    return;
}

void HS_POST_DestroyCtxPriv(void **priv)
{
    return;
}

INT32 HS_Post_Init(void)
{
    struct HS_hook_ops *ops = NULL;

    ops = hs_malloc(sizeof(struct HS_hook_ops));
    if (ops == NULL) {
    	goto ERROR;
    }

    INIT_LIST_HEAD(&ops->list);
    ops->hooknum = HS_HOOK_POST_DPI;
    ops->priority = HS_PLUGIN_POST;
    ops->uDependPluginList = 0;
    ops->bEnable = TRUE;
    ops->fn = HS_POST_Process;
    ops->destroy_fn = HS_POST_destroy;
    ops->pfnCtxPrivDestroy = HS_POST_DestroyCtxPriv;
    ops->priv = NULL;

    if (HS_RegisterHook(ops) != HS_OK) {
        goto ERROR;		
    }

    return HS_OK;
ERROR:
    if (ops != NULL) {
        HS_UnregisterHook(ops->hooknum, ops->priority);
        hs_free(ops);
    }

	return HS_ERR;
}

