#ifndef __HS_CORE_H_
#define __HS_CORE_H_

#if MODE == USERSPACE
#include <stdio.h>
#include <pthread.h>
#include <sys/time.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "hs_list.h"
#elif MODE == KERNELSPACE
#include <linux/list.h>
#include <linux/uaccess.h>
#endif

#include "hs.h"
#include "hs_consts.h"
#include "hs_alg.h"

#if MODE == USERSPACE
#define HS_LIB_PATH         "./"
#define HS_TMP_LIB			"./.dpi.lib."
#define HS_LIB_TMP_PATH     "./.dpi_lib_"
#define HS_LIB_FILE         HS_LIB_PATH"dpi.lib"
#define HS_LIB_DFA          "/dpi.dfa"
#define HS_LIB_INI          "/dpi.info"
#define HS_LIB_PBDL         "/dpi.pbdl"
#define HS_LIB_VERSION      "/dpi.ver"
#define HS_LICENSE          HS_LIB_PATH"hs.lic"
#define HS_INI_FILE		    HS_LIB_PATH"hs.ini"
#elif MODE == KERNELSPACE
#define HS_LIB_PATH         "/var/tmp/.dpi_lib/"
#define HS_LIB_FILE         HS_LIB_PATH"dpi.lib"
#define HS_LIB_DFA          HS_LIB_PATH"dpi.dfa"
#define HS_LIB_INI          HS_LIB_PATH"dpi.info"
#define HS_LIB_VERSION      HS_LIB_PATH"dpi.ver"
#define HS_INI_FILE		    HS_LIB_PATH"hs.ini"
#endif

#define HS_VER_VERSION      "version"
#define HS_VER_DATE         "date"
#define HS_VER_REVISION     "revision"
#define HS_VER_CATEGORY     "category"
#define HS_VER_SUB_CATEGORY "sub-category"
#define HS_VER_APPLICATION  "applicaiton"

typedef enum {
	HS_HOOK_PRE_DPI,
	HS_HOOK_DPI,
	HS_HOOK_POST_DPI,
	HS_HOOK_DFI,
	HS_HOOK_POST_DFI,
	HS_HOOK_MAX
} HS_HOOK_E;

typedef enum {
	HS_PLUGIN_CUSTOM,
	HS_PLUGIN_EXPECT,
	HS_PLUGIN_CONTENT,
	HS_PLUGIN_DFI,
	HS_PLUGIN_FTP,
	HS_PLUGIN_SKYPE,
	HS_PLUGIN_SIP,
	HS_PLUGIN_DNS,
	HS_PLUGIN_FAKE,
	HS_PLUGIN_PBDL,
	HS_PLUGIN_HOST,
	HS_PLUGIN_ACCOUNT,
	HS_PLUGIN_MOBILEINFO,
	HS_PLUGIN_SMTP,
	HS_PLUGIN_MAX
} HS_PLUGIN_E;       

#define PLUGIN_NAME_CUSTOM      "custom"
#define PLUGIN_NAME_EXPECT      "expect"
#define PLUGIN_NAME_CONTENT     "content"
#define PLUGIN_NAME_DFI         "dfi"
#define PLUGIN_NAME_SKYPE       "skype"
#define PLUGIN_NAME_FTP         "ftp"
#define PLUGIN_NAME_SIP         "sip"
#define PLUGIN_NAME_DNS         "dns"
#define PLUGIN_NAME_FAKE        "fake"
#define PLUGIN_NAME_PBDL        "pbdl"
#define PLUGIN_NAME_HOST        "host"
#define PLUGIN_NAME_ACCOUNT     "account"
#define PLUGIN_NAME_MOBILEINFO  "mobile_info"


typedef enum APP_ATTR_TYPE {
	APP_ATTR_EN,
	APP_ATTR_ZH,
	APP_ATTR_ID,
	APP_ATTR_P2P,
	APP_ATTR_FAKE,
    APP_ATTR_DNS,
    APP_ATTR_MT,
	APP_ATTR_HELP,
	APP_ATTR_MAX,
	APP_ATTR_UNKNOWN = APP_ATTR_MAX
} APP_ATTR_E;

#define APP_ATTR_NAME_LIST  \
    {                   \
    	"en",           \
    	"zh",           \
    	"id",           \
    	"p2p",          \
    	"fake",         \
    	"dns",          \
        "mt",           \
    	"help"          \
	}

typedef  UINT16 HS_HOOK_OFFSET_T;

enum _HS_flag_offset {
	HS_OFFSET_SUCCESS,
	HS_OFFSET_MARKED,
	HS_OFFSET_MAX
};

#define HS_FLAG_SUCCESS 	((UINT32)1 << HS_OFFSET_SUCCESS)
#define HS_FLAG_MARKED 	((UINT32)1 << HS_OFFSET_MARKED)

#define HS_DETECT_SUCCESS(flag)		((flag) & (HS_FLAG_SUCCESS))
#define HS_SET_DETECT_SUCCESS(flag)	((flag) |= HS_FLAG_SUCCESS)

#define HS_MARKED(flag)				((flag) & (HS_FLAG_MARKED))
#define HS_SET_MARKED(flag)			((flag) |= HS_FLAG_MARKED)	
#define HS_SET_UNMARKED(flag)			((flag) &= ~HS_FLAG_MARKED)

#define HS_INIT_FLAG(flag)				(flag &= 0x00000000U)

typedef struct {
	UINT32 uIpAddr;
	UINT16 usPort;
} HALF_TUPLE4_S;

struct buff_info {
    CHAR *buff;
    UINT32 *offset;
    UINT32 size; 
}; 

#if 0
#ifndef HS_CTX_S_DEFINED
#define HS_CTX_S_DEFINED
struct dfi_conn;
struct skype_conn;

typedef struct {
#if PDE_MODE == PDE_PACKET
    HS_rwlock_t stLock;
#endif
    HS_HOOK_OFFSET_T	arrusFastPath[HS_HOOK_MAX];
    atomic_t	atProcCount;
    UINT32		appid;
    UINT32		flag;
    UINT32 uHostHashIndex;
    UINT32 uiLocalUpgradeTimes;
    struct dfi_conn *conn;
    struct skype_conn *pstSkypeConn;
    HS_time_t	create_ts;
    HS_PLUGIN_E enPluginType;
    void *priv_data;
} HS_CTX_S;
#endif
#endif

#define HS_WRITE_LOCK_CTX(pstCtx)			HS_write_lock(&(pstCtx)->stLock)
#define HS_WRITE_UNLOCK_CTX(pstCtx)		    HS_write_unlock(&(pstCtx)->stLock)
#define HS_READ_LOCK_CTX(pstCtx)			HS_read_lock(&(pstCtx)->stLock)
#define HS_READ_UNLOCK_CTX(pstCtx)		    HS_read_unlock(&(pstCtx)->stLock)

static inline BOOL HS_IS_THIS_PLUGIN(HS_CTX_S *pstCtx, HS_PLUGIN_E enPluginType)	
{
	return pstCtx->enPluginType == HS_PLUGIN_MAX || pstCtx->enPluginType == enPluginType;
}

static inline void HS_SET_THIS_PLUGIN(HS_CTX_S *pstCtx, HS_PLUGIN_E enPluginType)	
{
	pstCtx->enPluginType = enPluginType;
}

#define HS_PROBE_SUCCESS(dpi) (g_bHsLibOk == FALSE ? 1: ((dpi)?HS_DETECT_SUCCESS(((HS_CTX_S *)(dpi))->flag):1))


extern MALLOC_FUNC hs_malloc;
extern CALLOC_FUNC hs_calloc;
extern REALLOC_FUNC hs_realloc;
extern FREE_FUNC hs_free;

typedef void (*HS_MATCH_NOTICE)(UINT16 app, void *arg);

typedef  HS_CTX_S* (*GET_CTX)(void* arg, HS_PKT_DETAIL_S *detail);

#define IS_UNKNOWN_ID(id) 	(((UINT32)id) == (UNKNOWN_ID) || ((UINT32)id) == MASK_VERSION(UNKNOWN_ID))
//#define IS_APP_OTHER_ID(id) 	(((UINT32)id) == (APP_OTHER_ID))
#define IS_LEAF_NODE(id)	(VERSION_ID(id))
#define IS_SUB_APP_NODE(id)  ((!VERSION_ID(id)) && SUB_APP_ID(id))
#define IS_APP_NODE(id)  ((!VERSION_ID(id)) && !SUB_APP_ID(id) && APP_ID(id))
#define IS_GROUP_NODE(id)  ((!VERSION_ID(id)) && !SUB_APP_ID(id) && !APP_ID(id) &&GROUP_ID(id) )

static inline BOOL HS_PLUGIN_MARKED(
	HS_CTX_S		*pstCtx,
	HS_HOOK_E		eHook,
	HS_PLUGIN_E	ePlugin)			
{
	return (BOOL)(pstCtx->arrusFastPath[eHook] & ((HS_HOOK_OFFSET_T)1 << ePlugin));
}

static inline BOOL HS_PLUGIN_UNMARKED(
	HS_CTX_S		*pstCtx,
	HS_HOOK_E		eHook,
	HS_PLUGIN_E	ePlugin)			
{
	return !(BOOL)(pstCtx->arrusFastPath[eHook] & ((HS_HOOK_OFFSET_T)1 << ePlugin));
}
static inline void HS_PLUGIN_SET_MARKED (
	HS_CTX_S		*pstCtx,
	HS_HOOK_E		eHook,
	HS_PLUGIN_E	ePlugin)
{
	pstCtx->arrusFastPath[eHook] |= ((HS_HOOK_OFFSET_T)1 << ePlugin);
	HS_SET_MARKED(pstCtx->flag);
}

static inline void HS_PLUGIN_SET_UNMARKED(
	HS_CTX_S		*pstCtx,
	HS_HOOK_E		eHook,
	HS_PLUGIN_E	ePlugin)
{
	int idx = 0;
	UINT32 flag = 0;
	
	pstCtx->arrusFastPath[eHook] &= ~((HS_HOOK_OFFSET_T)1 << ePlugin);

	for(; idx < HS_HOOK_MAX; idx++) {
		flag |= pstCtx->arrusFastPath[idx];
	}
	/* If there is no plugins, set the ctx->flag to be unmarked. */
	if(0 == flag) {
		HS_SET_UNMARKED(pstCtx->flag);
	}
}

static inline void HS_PLUGIN_SET_UNMARKED_ALL(HS_CTX_S *pstCtx)
{
	memset(pstCtx->arrusFastPath, 0, sizeof(pstCtx->arrusFastPath));
	HS_SET_UNMARKED(pstCtx->flag);
}

struct app_node *GetAppNode(UINT32 app_id);

static inline void HS_set_appid( HS_CTX_S *HS_ctx, UINT32 appid)
{
	HS_ctx->appid = (UINT32)appid;
}

#define GROUP_MASK					0xFF000000U
#define APP_MASK					0x00FF0000U
#define	SUB_APP_MASK				0x0000FF00U
#define VERSION_MASK				0x000000FFU

#define GROUP_ID(id)			((id) & (GROUP_MASK))
#define APP_ID(id)				((id) & (APP_MASK))
#define SUB_APP_ID(id)			((id) & (SUB_APP_MASK))
#define VERSION_ID(id)			((id) & (VERSION_MASK))

#define GROUP_INDEX(id)			((GROUP_ID(id)) >> 24)
#define APP_INDEX(id)			((APP_ID(id)) >> 16)
#define SUB_APP_INDEX(id)		(SUB_APP_ID(id) >> 8)
#define VERSION_INDEX(id)		((VERSION_ID(id)))

#define MASK_GROUP(id)			((id) & (~GROUP_MASK))
#define MASK_APP(id)			((id) & (~APP_MASK))
#define MASK_SUB_APP(id)		((id) & (~SUB_APP_MASK))
#define MASK_VERSION(id)		((id) & (~VERSION_MASK))

/* unknown app id */
#define UNKNOWN_ID (~(UINT32)0)

/* other app id */
#define APP_OTHER_ID_GROUP      (0xFE000000)
#define APP_OTHER_ID_DEFAULT    (0xFE010101)

#define HS_dereference(p) (p) 

typedef enum {
	APP_GROUP,
	APP_APP,
	APP_SUB_APP,
	APP_VERSION, 
	APP_MAX
} APP_LEVEL_E;

struct list_app_tree_info {
	void (*func)(APP_LEVEL_E enLevel, struct app_node *pstNode, void *arg);
	void *arg;
}; 

typedef struct {
	CHAR 		arrcEn[MAX_BUFF_LEN];
	CHAR 		arrcZh[MAX_BUFF_LEN];
	CHAR		arrcDns[DNS_BUFF_LEN];
	CHAR        arrcFake[MAX_BUFF_LEN];
	CHAR		arrcHelp[MAX_BUFF_LEN];
	BOOL		bP2p;
	BOOL 		bMultiThread;
	UINT32 		uId;
    UINT32      uParentId;
	atomic_t	session_count;
    size_t      traffic_count;
} APP_S;

struct alloc_t {
	UINT32 	size;
	UINT32	capacity;
	struct 	app_node **vec;
};

enum  NODE_TYPE {
	NODE_APP,
	NODE_OPS,
	NODE_MAX
};

/* HS_EXPECT_XXXXX 
			  |----> protocol
			   |----> dst ip
			    |---> dst port
			     |--> src ip
			      |-> src port

	HS_EXPECT_TXOXX
				 |-> Random
	HS_EXPECT_UXOXX
*/

enum HS_EXPECT_TYPE {
	HS_EXPECT_TXXXO,	/* tcp + dst-ip + dst-port + src-ip, for ftp */
	HS_EXPECT_UOOXX,	/* udp + src-ip + src-port, for p2p */
	HS_EXPECT_UXXOO,	/* udp + dst-ip + dst-port, for p2p */
	HS_EXPECT_MAX
};

typedef struct app_node {
	APP_S app;
	struct alloc_t children;
} APP_NODE_S;

// all the members should be freed after exit.
struct HS_desc_t {
	CHAR arrcVersion[MAX_BUFF_LEN];			
	CHAR arrcDate[MAX_BUFF_LEN];
	CHAR arrcRevision[MAX_BUFF_LEN];
    CHAR arrcCatetory[MAX_BUFF_LEN];
    CHAR arrcSubCatetory[MAX_BUFF_LEN];
    CHAR arrcApplication[MAX_BUFF_LEN];
};

typedef enum http_filed {
   HTTP_FIELD_METHOD,
   HTTP_FIELD_URI,
   HTTP_FIELD_HOST,
   HTTP_FIELD_PROXY_CONNECTION,
   HTTP_FIELD_REFERER,
   HTTP_FIELD_RANGE,
   HTTP_FIELD_USER_AGENT,
   HTTP_FIELD_CONTENT_TYPE,
   HTTP_FIELD_CONTENT_LENGTH,
   HTTP_FIELD_CONTENT,
   HTTP_FIELD_UNKNOWN,
   HTTP_FIELD_MAX = HTTP_FIELD_UNKNOWN
} HTTP_FIELD_TYPE_E;

typedef enum DFA_TYPE {
	DFA_TYPE_CONTENT_TCP,
    DFA_TYPE_CONTENT_UDP,
	DFA_TYPE_BEHAVIOR,
	DFA_TYPE_BEHAVIOR_V2,
	DFA_TYPE_PRE_CONTENT, 
	DFA_TYPE_POST_CONTENT,
	DFA_TYPE_CONTENT_HTTPS,
	DFA_TYPE_CONTENT_RTMP,
	DFA_TYPE_CONTENT_FILE_TYPE,
	DFA_TYPE_CONTENT_HTTP,
	DFA_TYPE_CONTENT_HTTP_BASE,
	DFA_TYPE_CONTENT_HTTP_END = DFA_TYPE_CONTENT_HTTP_BASE + HTTP_FIELD_MAX - 1,
	DFA_TYPE_CUSTOM_PRE_CNT,
	DFA_TYPE_CUSTOM_POST_CNT,
    DFA_TYPE_UNKNOWN,
    DFA_TYPE_MAX = DFA_TYPE_UNKNOWN
} DFA_TYPE_E;

struct dfa_t {
	struct list_head 	list;
	UINT32				id;	
	UINT32 				length;
	CHAR  				type[MAX_BUFF_LEN];
};

typedef struct {
	UINT32  uOffset;
	UINT32  uLen;
	UINT32  uByteSeq;
	INT32   iDelta;
} LENGTH_SIG_S;

typedef struct {
	UINT32 uAppId;
	LENGTH_SIG_S arrstLengthSig[2];
	INT32 iPriority;
} APP_EXTEND_S;

typedef struct graph_appid_list {
	APP_EXTEND_S arrAppExtend[MAX_APP - 1];
	UINT32 uSize;
} DFA_APPID_S;

typedef struct {
    DFA_TYPE_E enDfaType;
    unsigned int uDfaSeq;
} DATA_DFA_S;

typedef struct {
    DFA_TYPE_E enDfaType;
    unsigned int uNum;
    unsigned char arrucData[0];
} DATA_APPID_S;

typedef struct {
    unsigned int uNum;
    unsigned char arrucData[0];
} DATA_FIELD_APPID_S;

typedef enum {
    DATA_TYPE_DFA,
    DATA_TYPE_APPID,
    DATA_TYPE_FIELD_APPID,
    DATA_TYPE_MAX
} DATA_TYPE_E;

typedef struct _data_item {
    unsigned int uStepLen;
    DATA_TYPE_E enType;
} DATA_ITEM_S;

struct hash_data_node_t{
	const CHAR *pcEn;
    const CHAR *pcZh;
	APP_NODE_S *pstNode; 
};

typedef struct {
	/* maximum number of packets . */
    UINT16 usAppProbeNum;
    UINT16 usContentScanPacketNum;
    UINT16 usContentScanDataLen;

    UINT16 usDfiMaxScanNum;
    UINT16 usDfiAverLenScanNum;
    UINT16 usDfiRadioScanNum;
    
    UINT16 usHostProbeNum;

    UINT16 usTypicalMinP2pLoad;
    UINT16 usTypicalMinP2pPort;
	UINT16 usHostPostDfiStartSeq;

    UINT32 uPbdlMaxEventNum;

	UINT32 uMaxInnerIpNum;		/* 内网最大ip数，默认1w个 */
} HS_PARAM_S;

typedef struct {
    /* only MP can modify it's value, DP cann't do it, so atomic is not necessary. */
    UINT32 global_update_times; 
    UINT32 arrDfaNum[DFA_TYPE_MAX];
    DFA_S * arrDfaPtr[DFA_TYPE_MAX][DFA_PER_TYPE_MAX];
    struct graph_appid_list arrAppId[DFA_TYPE_MAX];

    APP_NODE_S app_root;								/* root node of app tree */
    HS_rwlock_t appdb_rwlock;							/* rwlock for protecting self-defined apps */
    struct HS_desc_t stDesc;							/* dpi description */
    struct list_head dfa_list;							/* list of dfa description */
    struct hash *app_hash;
    struct hash *app_hash2;
    struct list_head HS_Hooks[HS_HOOK_MAX];
    BOOL bDfiEnable;
    struct hash *expect_hash_list[HS_EXPECT_MAX];
    struct list_head pre_HS_custom_app_list;
    struct list_head post_HS_custom_app_list;
    struct list_head custom_group_list;

    /* Plugin: Host */
    struct hash *host_hash;
	struct list_head host_timeout;
	atomic_t host_num;
	HS_rwlock_t timeout_lock;
    
    UINT32 p2p_appid_num;
    UINT32 p2p_appid_list[HS_MAX_P2P_NUM];
    
    UINT32 http_multi_appid_num;
    UINT32 http_multi_appid_list[HS_MAX_HTTP_MULTI_NUM];
    
    UINT32 dns_appid_num;
    UINT32 dns_appid_list[HS_MAX_DNS_NUM];
    
    UINT32 fake_appid_num;
    UINT32 fake_appid_list[HS_MAX_FAKE_NUM];

    /* add save pbdl module used appid list for search by chenjd begin */
    UINT32 uiPbdlAppidListNum;
    UINT32 arrPbdlAppidList[HS_PBDL_MAX_APP_NUM];
    /* add save pbdl module used appid list for search by chenjd end */
	CHAR lib_dir[MAX_BUFF_LEN];
	CHAR lib_dfa[MAX_BUFF_LEN];
	CHAR lib_ini[MAX_BUFF_LEN];
	CHAR lib_pbdl[MAX_BUFF_LEN];
	CHAR lib_version[MAX_BUFF_LEN];
} HS_DATA_S;

typedef enum {
    ADDRESS_INVALID,
    ADDRESS_IP,
    ADDRESS_RANGE,
    ADDRESS_MASK
} ADDRESS_TYPE_E;

typedef struct {
    UINT32  uInvert;
    ADDRESS_TYPE_E eType;
    union {
        struct {
            UINT32 lower;
            UINT32 upper;
        } stRange;

        struct {
            UINT32 ip; 
            UINT32 mask;
        } stMask;
    
        UINT32 ip; 
    } uData;
} ADDRESS_S;

#define MAX_ADDRESS_SIZE   64

typedef struct {
    UINT32          uNum;
    ADDRESS_S       arrAddress[MAX_ADDRESS_SIZE];
} ADDRESS_INFO_S;

UINT32 GetAppId(const char *app_name);

static inline boolean app_has_one_child(UINT32 appid)
{
	APP_NODE_S *pstNode = GetAppNode(appid);	
	if( !pstNode) {
		return FALSE;	
	}

	if(pstNode->children.size == 1)
		return TRUE;
	
	return FALSE;
}

typedef INT32 WALK_CALLBACK(UINT32 child_id, void *arg);
 
typedef INT32 WALK_CALLBACK_DIRECT(APP_NODE_S *pstNode, void *arg);

typedef INT32 WALK_CALLBACK_BY_LEVEL(UINT32 child_id, void *arg, void **next_level_arg);
 
typedef INT32 WALK_CALLBACK_DIRECT_BY_LEVEL(APP_NODE_S *pstNode, void *arg, void **next_level_arg);

/*
 * HS_WALK: walk through all the children of the parent group, if the children is valid, callback will be 
 * invoked. if the callback's return value is not HS_OK, the walk would break.
 *		@parent_id:	the parent group's id.
 *		@callback: callback function invoked through walk, whose prototype is INT32(*)(size_t, void *), be careful!
 * 		@arg: the argument of the 'callback' function.
 * return value:
 *		- HS_OK: walk successfully. 
 *		- HS_ERR: walk failed, maybe the callback return HS_ERR.
 */
INT32 HS_WALK(UINT32 parent_id, WALK_CALLBACK callback, void *arg);

INT32 HS_WALK_direct(UINT32 parent_id, WALK_CALLBACK_DIRECT callback, void *arg);

INT32 HS_WALK_recursive(UINT32 parent_id, WALK_CALLBACK callback, void *arg);

INT32 HS_WALK_recursive_direct(UINT32 parent_id, WALK_CALLBACK_DIRECT callback, void *arg);

INT32 HS_WALK_recursive_direct_by_level(UINT32 parent_id, WALK_CALLBACK_DIRECT_BY_LEVEL \
		callback, void *arg);

void HS_GetInnerIp(HS_PKT_DETAIL_S *detail, UINT32 *ipaddr, UINT16 *port);

typedef INT32 (*HS_hookfn)(HS_CTX_S *ctx, HS_PKT_DETAIL_S *detail, void **priv);
typedef void (*HS_hook_destroyfn)(void **priv); 
typedef void (*HS_ctx_priv_destroyfn)(void **priv); 

enum HOOK_ACTION {
	HOOK_ACTION_CONTINUE,
	HOOK_ACTION_BREAK,
	HOOK_ACTION_MAX,
};

typedef struct HS_hook_ops {
	struct list_head list;
	INT32 hooknum;
	INT32 priority;
	UINT32 uDependPluginList;
	BOOL bEnable;
	HS_hookfn fn;
	HS_hook_destroyfn destroy_fn;
	HS_ctx_priv_destroyfn pfnCtxPrivDestroy; /* free HS_ctx->priv_data if this plugin has been unloaded.*/
	void *priv;
} HS_HOOK_OPS_S;

INT32 HS_RegisterHook(struct HS_hook_ops *req);

struct HS_hook_ops *HS_UnregisterHook(INT32 hooknum, INT32 priority);

struct HS_hook_ops *HS_ReferHook(INT32 pos, INT32 priority);

#if MODE == KERNELSPACE
IAPF_FILE IAPF_Open_Imp(CHAR *file, INT32 flags, INT32 mode, mm_segment_t *cur_fs);

INT32 IAPF_Close_Imp(IAPF_FILE fp, mm_segment_t *cur_fs);
#endif

void *HS_Malloc(size_t size);
void HS_Free(void *ptr);
void *HS_Realloc(void *pvOld, size_t ulNewSize);
void *HS_Calloc(size_t ulSize);

#endif
