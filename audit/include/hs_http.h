#ifndef _HS_HTTP_H_
#define _HS_HTTP_H_

#define HTTP_FIELD_STR_HOST                 "Host"
#define HTTP_FIELD_STR_PROXY_CONNECTION     "Proxy-Connection"
#define HTTP_FIELD_STR_REFERER              "Referer"
#define HTTP_FIELD_STR_RANGE                "Range"
#define HTTP_FIELD_STR_USER_AGENT           "User-Agent"
#define HTTP_FIELD_STR_CONTENT_TYPE         "Content-Type"
#define HTTP_FIELD_STR_CONTENT_LENGTH       "Content-Length"

#define HTTP_FIELD_LEN_HOST                 sizeof(HTTP_FIELD_STR_HOST)
#define HTTP_FIELD_LEN_PROXY_CONNECTION     sizeof(HTTP_FIELD_STR_PROXY_CONNECTION)
#define HTTP_FIELD_LEN_REFERER              sizeof(HTTP_FIELD_STR_REFERER)
#define HTTP_FIELD_LEN_RANGE                sizeof(HTTP_FIELD_STR_RANGE)
#define HTTP_FIELD_LEN_USER_AGENT           sizeof(HTTP_FIELD_STR_USER_AGENT)
#define HTTP_FIELD_LEN_CONTENT_TYPE         sizeof(HTTP_FIELD_STR_CONTENT_TYPE)
#define HTTP_FIELD_LEN_CONTENT_LENGTH       sizeof(HTTP_FIELD_STR_CONTENT_LENGTH)
#define HTTP_FIELD_LEN_MAX                  HTTP_FIELD_LEN_PROXY_CONNECTION

#define HTTP_FIELD_LEN_NUM_MAX              2
#define MAX_STATE_NUM                       8

typedef struct field_info {
    UCHAR *pucData;
    UINT32 uLen;
} HTTP_FIELD_INFO_S;

typedef UINT16 HTTP_FIELD_MATCH_S;

typedef struct http_head {
    HTTP_FIELD_INFO_S arrInfo[HTTP_FIELD_MAX];
} HTTP_HEAD_INFO_S;

typedef struct http_head_match {
#if HTTP_DFA_ID_LENGTH == 4
    UINT32 arruMatch[HTTP_FIELD_MAX][RULE_ID_MAX];
#else
    UINT16 arruMatch[HTTP_FIELD_MAX][RULE_ID_MAX];
#endif
    UINT32 arruNum[HTTP_FIELD_MAX];
} HTTP_HEAD_MATCH_S;

typedef enum {
    MATCH_RT_OK,
    MATCH_RT_ERR_ABORT,
    MATCH_RT_ERR_ARR_FULL,
    MATCH_RT_ERR_MAX
} MATCH_RT_E;

/*
 * HTTP_LocateCRLF: 
 *      @pucData: the start position of data;
 *      @uLen: length of the data;
 * Return Value:
 *      the location of the chars of "\r\n", return NULL if not found.
 * */
static inline UCHAR * HTTP_LocateCRLF(UCHAR *pucData, UINT32 uLen)
{
    UCHAR *pucPtr = pucData;
    
    if(uLen < 2) {
        return NULL; 
    }

    for (pucPtr = pucData; pucPtr < pucData + uLen - 1; pucPtr++) {
        if (*pucPtr == CR && *(pucPtr + 1) == LF) {
            return pucPtr; 
        }
    }

    return NULL;
}

/*
 * HTTP_LocateColonBlank: 
 *      @pucData: the start position of data;
 *      @uLen: length of the data;
 * Return Value:
 *      the location of the chars of ": ", return NULL if not found.
 * */
static inline UCHAR * HTTP_LocateColonBlank(UCHAR *pucData, UINT32 uLen)
{
    UCHAR *pucPtr = pucData;

    for (pucPtr = pucData; pucPtr < pucData + uLen - 1; pucPtr++) {
        if (*pucPtr == ':' && *(pucPtr + 1) == ' ') {
            return pucPtr; 
        }
    }

    return NULL;
}

INT32 HTTP_RequestParse(HTTP_HEAD_INFO_S *pstHeadInfo, HS_PKT_DETAIL_S *pstDetail);

UINT32 HTTP_RequestProcess(HS_PKT_DETAIL_S *pstDetail);

void Init_HttpFiledMap(void);

UINT32 AssignLogName(const CHAR *pcLogMod, HS_time_t tv, CHAR *pcLogName, UINT32 uLogNameLen);

#endif
