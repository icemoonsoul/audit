#ifndef __HS_H_
#define __HS_H_

#if MODE == USERSPACE
#include <sys/time.h>
#elif MODE == KERNELSPACE
#include <net/netfilter/nf_conntrack.h>
#endif

#include "hs_types.h"

#define HS_OK           ((INT32)0)
#define HS_ERR			((INT32)~0)

#define DIR_C2S		    0
#define DIR_S2C		    1


enum {
    SIDE_UNKNOWN,
    SIDE_IN,
    SIDE_OUT
};

typedef enum {
	LANG_EN,
	LANG_ZH,
	LANG_MAX
} LANG_TYPE;

#ifndef STRUCT_TUPLE4
#define STRUCT_TUPLE4
struct tuple4
{
  UINT16 source;
  UINT16 dest;
  UINT32 saddr;
  UINT32 daddr;
};
#endif

struct tuple5 {
	UINT32	protocol;	
	struct tuple4 addr;
};

typedef struct {
    UINT32 uGroupNum;
    UINT32 uAppNum;
    UINT32 uSubAppNum;
} APP_NUM_S;

typedef struct pkt_detail {
    UINT32 uProcCount;
	struct tuple5 tuple;
	INT32 side; 		/* outside or inside */
	INT32 direct; 		/* client or server */
	UINT32 length; 
	UCHAR *data;
	HS_time_t ts;
} HS_PKT_DETAIL_S;

typedef struct {
    HS_rwlock_t stLock;
    UINT16	    arrusFastPath[5];
    atomic_t	atProcCount;
    UINT32		appid;
    UINT32		flag;
    UINT32      uHostHashIndex;
    UINT32      uiLocalUpgradeTimes;
    struct dfi_conn *conn;
    struct skype_conn *pstSkypeConn;
    struct app_account *pstAccount;
    struct mobile_info *pstMobileInfo;
    HS_time_t	create_ts;
    INT32       enPluginType;
    void        *priv_data;
} HS_CTX_S;


extern UINT32 g_uAppOther;

/* counter of the update times. */
extern UINT32 g_uHsUpgradeTimes;

void HS_InitCtx(HS_CTX_S *ctx, HS_time_t ts);

/*
 * HS_IsUnknownId: check that whether this appid is unknown id.
 * 		@appid: the appid of the session;
 * */
extern BOOL HS_IsUnknownId(UINT32 appid);

/* HS_CTX_MARKED: check whether this session is marked, if is marked, this session would be \
 * detected until be unmarked or closed.
 * 		@ctx: the pointer to the private data's address;
 * 	return value:
 * 		- TRUE: marked.
 * 		- FALSE: unmarked.
 * */
			
extern BOOL HS_CTX_MARKED(HS_CTX_S *ctx);
							

/* HS_CTX_SUCCESS: check whether this session is detected out.
 * 		@ctx: the pointer to the private data's address;
 * 	return value:
 * 		- TRUE: detected out.
 * 		- FALSE: not detected out.
 * */
extern BOOL HS_CTX_SUCCESS(HS_CTX_S *ctx);

/*
 * HS_Load: load HyperScan module.  
 *  	@_hs_malloc: the memory allocation function;
 * 		@_hs_free: the memory free function;
 *		@pcLibFile: the location of the library;
 *      @pcIniFile: the location of the ini configure file;
 * return value:
 * 		- HS_OK: load successfully. 
 * 		- HS_ERR: load failed. 
 */
INT32 HS_Load(MALLOC_FUNC _hs_malloc, FREE_FUNC _hs_free, CHAR *pcLibFile, CHAR *pcIniFile);

/*
 * HS_Update: update HyperScan module.
 *		@pcLibFile: the location of the library;
 * return value:
 * 		- HS_OK: update successfully. 
 * 		- HS_ERR: update failed. 
 */
extern INT32 HS_Update(CHAR *pcLibFile);

/*
 * HS_Unload: unload HyperScan module. 
 * return value:
 * 		- HS_OK: unload successfully. 
 * 		- HS_ERR: unload failed.
 */
extern INT32 HS_Unload(void);

/*
 * HS_Probe: identify the application type of this packet/session, appid be gotten from ctx.
 * 		@ctx: private data which is used by HyperScan engine;
 * 		@pstDetail: detail information of this packet;
 * return value:
 * 		- HS_OK: ok, but don't mean that the application is identified out. 
 * 		- HS_ERR: probe failed.
 */
extern INT32 HS_Probe(HS_CTX_S *ctx, HS_PKT_DETAIL_S *pstDetail);

/*
 * HS_DestroyCtx: free the private data owned by HyperScan.	
 * 		@ctx: the pointer to the private data's address;
 * return value:
 * 		none
 * */
void HS_DestroyCtx(HS_CTX_S *ctx);

/* 
 * HS_version: show the HyperScan engine's version and the signature library's version. 
 * return value: 
 *      - none
 * */
extern void HS_version(void);

/* 
 * HS_GetAppIdFromCtx: get the appid of this session from the private data.
 * 		@ctx: the pointer to the private data's address;
 * return value:
 * 		- appid
 * */
UINT32 HS_GetAppIdFromCtx(HS_CTX_S *ctx);

/*
 * HS_GetProbeCount: get the packet's sequence number where this session has been detected out.
 * 		@ctx: the pointer to the private data's address;
 * 	return value:
 * 		- the packet sequence number.
 * */
//extern UINT32 HS_GetProbeCount(void **ctx);

/*
 * HS_IncAppCount: increase the count of this application.
 * 		@appid: the appid of the session;
 * return value:
 * 		- none
 * */
extern void HS_IncAppCount(UINT32 appid);

/*
 * HS_IncApppTrafficCount: increase the count of this application traffic.
 * 		@appid: the appid of the session;
 *      @traffic_count: the count of this kind of app.
 * return value:
 * 		- none
 * */
void HS_IncAppTrafficCount(UINT32 appid, UINT32 traffic_count);

/*
 * HS_ShowAppStat: show the statistics of HyperScan module.
 * return value: 
 * 		- none
 * */
#if MODE == USERSPACE
extern void HS_ShowAppStat(void);
#elif MODE == KERNELSPACE
extern void HS_ShowAppStat(CHAR *arrcBuff, UINT32 uSize, UINT32 *puOffset);
#endif

/*
 * HS_ListGroup: list all the applications of this group in the signature library.
 * 		@pcGroupName: the name of the application group;
 * 	return value:
 * 		- HS_OK: list successfully. 
 * 		- HS_ERR: list failed.
 * */
extern INT32 HS_ListGroup(const CHAR *pcGroupName);

/*
 * HS_ListAll: list all the applications in the signature library.
 * 	return value:
 * 		- HS_OK: list successfully. 
 * 		- HS_ERR: list failed.
 * */
extern INT32 HS_ListAll(void);

/* 
 * HS_AddInnerIp: add an inner ip.
 * 		@pcInnerIp: ip address would be added, such as "192.168.1.1", "192.168.1.0/24" and "192.168.1.10-192.168.1.100".
 * 	return value:
 * 		- none
 * */
extern void HS_AddInnerIp(const CHAR *pcInnerIp);

/* 
 * HS_FindAppIdByAppName: get the appid of the application specified by the name. 
 *		@pcAppName: the name of the application;
 * 		@lang: language type;
 * return value:
 *		the id of the application, return UNKNOWN_ID if failed to find.
 */
extern UINT32 HS_FindAppIdByAppName(const CHAR *pcAppName, LANG_TYPE lang);

/* 
 * HS_FindAppNameByAppId: get the name of the application specified by the appid. 
 *		@appid: the id of the application;
 * 		@lang: language type;
 *		@pcName: buffer where app_name would been stored.
 *		@uLen: the length of this buffer.
 * return value:
 * 		- HS_OK: find successfully. 
 * 		- HS_ERR: find failed.
 */
extern INT32 HS_FindAppNameByAppId(UINT32 appid, LANG_TYPE lang, CHAR *pcName, UINT32 uLen);

/*
 * IsHttpRequestHeader:check whether this packet is http request.
 *      @pstDetail:detail information of this packet;
 **/
BOOL IsHttpRequestHeader(HS_PKT_DETAIL_S *pstDetail);

#endif
