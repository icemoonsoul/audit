#ifndef _HS_FAKE_H_
#define _HS_FAKE_H_

/**************************************************************************
 * fake plugin
 *************************************************************************/
#define RTMP_MAX_SCAN_NUM       7
#define DOWNLOAD_MAX_SCAN_NUM   3
#define HTTPS_MAX_SCAN_NUM      3
#define FAKE_MAX_SCAN_NUM       6

typedef struct {
    struct list_head stList;
    UINT32 uAppId;
    UINT32 uTransAppId;
    UINT32 uDstAppId;
} FAKE_APP_S;

typedef struct {   
    UINT32 uTransAppId;
    UINT32 uDstAppId;
} FAKE_DATA_S;

INT32 HS_FAKE_Init(void);

#endif
