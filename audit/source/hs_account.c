#if MODE == USERSPACE
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#endif

#include "hs.h"
#include "hs_consts.h"
#include "hs_core.h"
#include "hs_stat.h"
#include "hs_account.h"

HS_rwlock_t g_stAccountRwlock;
LIST_HEAD_S g_stAccountHookHead;

static u32 g_appid_qq_chat_mobile;
static u32 g_appid_weixin_mobile;
static u32 g_appid_weixin_mobile_2;



static u32 g_appid_qq_chat;
static u32 g_appid_wang_wang_chat;
static u32 g_appid_fetion;
static u32 g_appid_sina_weibo;
static u32 g_appid_126mail_login;
static u32 g_appid_126mail_send;
static u32 g_appid_163mail_login;
static u32 g_appid_163mail_send;
static u32 g_appid_baidu_login;
static u32 g_appid_wangyiweibo_login;
static u32 g_appid_douban_login;
static UINT32 g_appid_smtp;
static UINT32 g_appid_pop3;
static UINT32 g_appid_maopu_login;
static UINT32 g_appid_maopu_browser;
static UINT32 g_appid_tencent_weibo_browser;
static UINT32 g_appid_tencent_weibo_posts;
static UINT32 g_appid_renren_login;

extern UCHAR *DPI_StrnStr(UCHAR *pu8Src, UCHAR *pu8Sub, UINT32 u32SrcLen);

char g_appid_action[ACCOUNT_MAX][ACCOUNT_ACTION_LEN];

typedef INT32 (*ACCOUNT_HOOK_PFUNC)(HS_CTX_S *pstCtx, HS_PKT_DETAIL_S *pstDetail, void *priv);
typedef INT32 (*ACCOUNT_DESTROY_PFUNC)(void *);

typedef struct account_hook {
    ACCOUNT_HOOK_E type;
    LIST_HEAD_S node;
    ACCOUNT_HOOK_PFUNC func;
    ACCOUNT_DESTROY_PFUNC destroy_func;
    void *priv;
} ACCOUNT_HOOK_S;

UINT32 g_uNodeAccountNum = 0;

/*暂时把账号相关信息直接写入代码*/
/*随后会保存到文件，通过读取文件来初始化*/
ACCOUNT_NODE_ASCII_S g_stNodeAccount_Ascii[ACCOUNT_NODE_NUM] = {
	{"tian-ya-lun-tan_1",  "userid=",    '&',          "%40", "@", 1},
	{"xi-ci-hu-tong_1",    "username=",  '&',          "%40", "@", 1},
	{"bai-du-tie-ba_1",    "userName=",  '&',          "%40", "@", 1},          //replace
	{"mao-pu_1",           "loginName=", '&',          "%40", "@", 1},
	{"wang-yi-163_1",      "P_INFO=",    '|',          "%40", "@", 1},
	{"qq-kong-jian_1",     "o_cookie=",  ';',          "%40", "@", 1},
	{"xin-lang-lun-tan_1", "name%3D",    '%',          "%2540", "@", 2},      //replace,  special process
	{"tie-xue-lun-tan_1",  "username=",  '&',          "%40", "@", 1},         
	{"hai-nan-zai-xian_1", "user=w=u%u005f", '&',      "%40", "@", 1},  
	{"zhong-hua-wang_1",   "username=",  '&',          "%40", "@", 1},     
	{"da-zhong-lun-tan_1", "username=",  '&',          "%40", "@", 1},
	{"da-he-lun-tan_1",    "username=",  '&',          "%40", "@", 1},
	{"long-chang-zai-xian_1",       "username=", '\r', "%40", "@", 1},
	{"zhong-guo-nei-jiang-wang_1",  "username=", '&',  "%40", "@", 1},
    {"nei-jiang-di-yi-cheng_1",     "username=", '&',  "%40", "@", 1},      
    {"han-an-tang_1",               "username=", '&',  "%40", "@", 1},  
    {"ning-xia-wang-chong_1",       "username=", '&',  "%40", "@", 1}, 
    {"hai-tang-she-qu_1",           "username=", '&',  "%40", "@", 1},
    {"de-yang-quan-sou-suo_1",      "username=", '&',  "%40", "@", 1}, 
    {"de-yang-zai-xian_1",          "username=", '&',  "%40", "@", 1},
    {"liang-shan-zai-xian_1",       "username=", '&',  "%40", "@", 1},
    {"liang-shan-zai-xian_2",       "username=", '&',  "%40", "@", 1},
    {"xi-chang-zai-xian_1",         "username=", '&',  "%40", "@", 1},
    {"tian-fu-she-qu_1",            "username=", '&',  "%40", "@", 1},
    {"long-chang-zai-xian_1",       "username=", '&',  "%40", "@", 1},
    {"xin-lang-you-xiang_1",        "name%3D",   '%',  "%2540", "@", 2},

    {"sou-hu-you-xiang_1",          "pp_login_time=https|",   '|',  "%2540", "@", 1},
    {"qq-you-xiang_1",              "qqmail_alias=",          ';',  "%2540", "@", 1},  
    {"189-you-xiang_1",             "189ACCOUNT=",            '\r', "%2540", "@", 1},
    {"139-you-xiang_1",             "Login_UserNumber=",      ';',  "%2540", "@", 1},
    {"21cn-you-xiang_1",            "21CNACCOUNT=",           '\r', "%2540", "@", 1},
    {"qu-na-er_1",                  "QN42=",                  ';',  "%2540", "@", 1},
    {"jing-dong_1",                 "_pst=",                  ';',  "%2540", "@", 1},
    {"gan-ji-wang_1",               "GanjiUserName=",         ';',  "%2540", "@", 1},
    {"dang-dang_1",                 "uname=",                 '&',  "%2540", "@", 1},
    {"pai-pai-wang_1",              "pin=",                   ';',  "%2540", "@", 1},
    {"zhai-ji-song_1",              "username=",              '&',  "%2540", "@", 1},
    {"zhong-guan-cun-zai-xian_1",   "zol_userid=",            ';',  "%2540", "@", 1},
    {"su-ning-yi-gou_1",            "&_snmb=",                '%',  "%2540", "@", 1}, 
    {"meng-ba-sha_1",               "DefaultCusName=",        ';',  "%2540", "@", 1},
    {"le-feng-wang_1",                 "lafaso_login_name_as988=", ';',  "%2540", "@", 1},
    {"you-gou-shi-shang-shang-cheng_1", "belle_username=",         ';',  "%2540", "@", 1},

    {"sina-weibo-mobile_1",       "X-Log-Uid: ",         '\r',  "%2540", "@", 1},
    {"qq-weibo-mobile_1",         "p_uin=o",             ';',  "%2540", "@", 1},
    {"yi-xin_1",                  "mobile=",             ' ',  "%2540", "@", 1},
    {"lai-wang_1",                "uid=",                '&',  "%2540", "@", 1},
    {"mo-mo_1",                   "X-KV: ",              '\r', "%2540", "@", 1},
    {"tao-bao-mobile_2",          "tracknick=",          ';', "%2540", "@", 1},

    {"wei-pin-hui-mobile_1",      "userid=",              '&', "%2540", "@", 1},
    {"e-le-me-mobile_1",          "USERID=",              ';', "%2540", "@", 1},


    /*注意不要越界，END 为结束标志*/
	{"END", "", ' '},
};

INT32 ACCOUNT_RegisterHook(ACCOUNT_HOOK_S *pstHook)
{
    ACCOUNT_HOOK_S *pstPos;
    assert(pstHook != NULL);

    if (pstHook->type < 0 ||  pstHook->type >= ACCOUNT_MAX) {
        return HS_ERR;
    }

    /* avoid dumplicate */
    HS_read_lock(&g_stAccountRwlock);

    list_for_each_entry(pstPos, &g_stAccountHookHead, node) {
        if (pstPos->type == pstHook->type) {
            HS_read_unlock(&g_stAccountRwlock);
            return HS_ERR;
        }
    }

    HS_read_unlock(&g_stAccountRwlock);

    HS_write_lock(&g_stAccountRwlock);
    
    list_add_tail(&pstHook->node, &g_stAccountHookHead);

    HS_write_unlock(&g_stAccountRwlock);

    return HS_OK;
}

void ACCOUNT_UnRegisterHook(ACCOUNT_HOOK_E enType)
{
    ACCOUNT_HOOK_S *pstHook, *pstTmp;
    
    HS_write_lock(&g_stAccountRwlock);

    list_for_each_entry_safe(pstHook, pstTmp, &g_stAccountHookHead, node) {
        if (pstHook->type == enType) {
            list_del(&pstHook->node);
            pstHook->destroy_func(pstHook->priv);
            hs_free(pstHook);
            break;
        }
    }

    HS_write_unlock(&g_stAccountRwlock);

    return;
}

INT32 ACCOUNT_CreateHook(ACCOUNT_HOOK_E enType, ACCOUNT_HOOK_PFUNC pfunc, ACCOUNT_DESTROY_PFUNC pfuncDestroy, void *priv)
{
    ACCOUNT_HOOK_S *pstHook;

    pstHook = hs_malloc(sizeof(ACCOUNT_HOOK_S));
    if (pstHook == NULL) {
        return HS_ERR;
    }

    memset(pstHook, 0, sizeof(ACCOUNT_HOOK_S));

    pstHook->type = enType;
    INIT_LIST_HEAD(&pstHook->node);
    pstHook->func = pfunc;
    pstHook->destroy_func = pfuncDestroy;
    pstHook->priv = priv;

    if (ACCOUNT_RegisterHook(pstHook) != HS_OK) {
        hs_free(pstHook);
        return HS_ERR;
    }

    return HS_OK;
}


VOID Account_InitGlobal()
{
    UINT32    uIndex = 0;
    UINT32    uAppid = 0;
    ACCOUNT_NODE_ASCII_S  *pstNode = NULL;

    for (uIndex = 0; uIndex < ACCOUNT_NODE_NUM; uIndex++)
    {
        pstNode = &(g_stNodeAccount_Ascii[uIndex]);
        if (0 == strncmp(pstNode->name, "END", 3))
        {
            break;
        }

        uAppid = HS_FindAppIdByAppName(pstNode->name, LANG_EN);
        pstNode->appid = uAppid;
        pstNode->sig_start_len = strlen(pstNode->sig_start);
        g_uNodeAccountNum++;
        //printf("Num %2d:  %-30s  %x\r\n", g_uNodeAccountNum, pstNode->name, pstNode->appid);
    }

}

INT32 CtxAssignAccount(HS_CTX_S *pstCtx, DPI_ACCOUNT_E enType, CHAR cFlag, CHAR *pcAccount, UINT32 uAccountLen)
{
    APP_ACCOUNT_S *pstAccount;

    pstAccount = hs_malloc(sizeof(APP_ACCOUNT_S));
    if (pstAccount == NULL) {
        return HS_ERR;
    }
    
    memset(pstAccount, 0, sizeof(APP_ACCOUNT_S));
    pstAccount->account_type = enType;
    pstAccount->flag = cFlag;

    // SSP_StrnCpy will be ok.
    if (uAccountLen >= ACCOUNT_MAX_LEN) {
        strncpy(pstCtx->pstAccount->account_buff, pcAccount, ACCOUNT_MAX_LEN - 1);
        pstCtx->pstAccount->account_buff[ACCOUNT_MAX_LEN - 1] = '\0';
    } else {
        strncpy(pstCtx->pstAccount->account_buff, pcAccount, uAccountLen);
        pstCtx->pstAccount->account_buff[uAccountLen] = '\0';
    }

    HS_WRITE_LOCK_CTX(pstCtx);
    if (pstCtx->pstAccount != NULL) {
        hs_free(pstAccount);
        HS_WRITE_UNLOCK_CTX(pstCtx);
        return HS_ERR;
    } else {
        pstCtx->pstAccount = pstAccount;
    }
    HS_WRITE_UNLOCK_CTX(pstCtx);

    HS_PLUGIN_IDENTIFY_STAT(HS_PLUGIN_ACCOUNT);

    return HS_OK;
}

static int DPI_ACCOUNT_InitGlobal(void)
{
    strncpy(g_appid_action[ACCOUNT_QQ_CHAT], VIRACC_ACTION_LOGIN, ACCOUNT_ACTION_LEN);
    strncpy(g_appid_action[ACCOUNT_QQ_CHAT_SENDMSG], VIRACC_ACTION_SENDMSG, ACCOUNT_ACTION_LEN);
    strncpy(g_appid_action[ACCOUNT_WANG_WANG_CHAT], VIRACC_ACTION_SENDMSG, ACCOUNT_ACTION_LEN);
    strncpy(g_appid_action[ACCOUNT_FETION], VIRACC_ACTION_LOGIN, ACCOUNT_ACTION_LEN);
    strncpy(g_appid_action[ACCOUNT_SINA_WEI_BO], VIRACC_ACTION_LOGIN, ACCOUNT_ACTION_LEN);
    strncpy(g_appid_action[ACCOUNT_126MAIL_LOGIN], VIRACC_ACTION_LOGIN, ACCOUNT_ACTION_LEN);
    strncpy(g_appid_action[ACCOUNT_126MAIL_SEND], VIRACC_ACTION_SENDMAIL, ACCOUNT_ACTION_LEN);
    strncpy(g_appid_action[ACCOUNT_163MAIL_LOGIN], VIRACC_ACTION_LOGIN, ACCOUNT_ACTION_LEN);
    strncpy(g_appid_action[ACCOUNT_163MAIL_SEND], VIRACC_ACTION_SENDMAIL, ACCOUNT_ACTION_LEN);
    strncpy(g_appid_action[ACCOUNT_BAIDU_LOGIN], VIRACC_ACTION_LOGIN, ACCOUNT_ACTION_LEN);
    strncpy(g_appid_action[ACCOUNT_WANGYIWEIBO_LOGIN], VIRACC_ACTION_LOGIN, ACCOUNT_ACTION_LEN);
    strncpy(g_appid_action[ACCOUNT_SMTP], VIRACC_ACTION_LOGIN, ACCOUNT_ACTION_LEN);
    strncpy(g_appid_action[ACCOUNT_POP3], VIRACC_ACTION_LOGIN, ACCOUNT_ACTION_LEN);
    strncpy(g_appid_action[ACCOUNT_MAOPU_LOGIN], VIRACC_ACTION_LOGIN, ACCOUNT_ACTION_LEN);
    strncpy(g_appid_action[ACCOUNT_MAOPU_BROWSER], VIRACC_ACTION_BROWSER, ACCOUNT_ACTION_LEN);
    strncpy(g_appid_action[ACCOUNT_TENCENT_WEIBO_BROWSER], VIRACC_ACTION_BROWSER, ACCOUNT_ACTION_LEN);
    strncpy(g_appid_action[ACCOUNT_TENCENT_WEIBO_POSTS], VIRACC_ACTION_POSTS, ACCOUNT_ACTION_LEN);
    strncpy(g_appid_action[ACCOUNT_RENREN_LOGIN], VIRACC_ACTION_LOGIN, ACCOUNT_ACTION_LEN);
    strncpy(g_appid_action[ACCOUNT_WANGYIWEIBO_LOGIN], VIRACC_ACTION_LOGIN, ACCOUNT_ACTION_LEN);
    strncpy(g_appid_action[ACCOUNT_DOUBAN_LOGIN], VIRACC_ACTION_LOGIN, ACCOUNT_ACTION_LEN);
    return HS_OK;
}

UCHAR *DPI_StrnChr(UCHAR *pucSrc, UCHAR ucSub, UINT32 uSrcLen, UINT32  uSeq)
{
    UINT32 uIndex = 0;

    if (NULL == pucSrc)
    {
        return NULL;
    }

    for (uIndex = 0; uIndex < uSrcLen; uIndex++)
    {
        if (*(pucSrc+uIndex) == ucSub)
        {
            uSeq--;
        }

        if (0 == uSeq)
        {
            return (pucSrc + uIndex);
        }
    }

    return NULL;
}

UCHAR *DPI_StrnStr(UCHAR *pucSrc, UCHAR *pucSub, UINT32 uSrcLen)
{
    UINT32 uSubLen = 0;
    UCHAR *pucTmp;
    UCHAR *pucPos;
    UCHAR *pucGuard;

    if (NULL == pucSrc || NULL == pucSub)
    {
        return NULL;
    }
    
    uSubLen = strlen(pucSub);

    if (uSubLen > uSrcLen) {
        return NULL;  
    }

    pucGuard = pucSrc + uSrcLen - uSubLen;
    pucPos = pucSrc;
    while (pucPos <= pucGuard && (pucTmp = memchr(pucPos, *pucSub, uSrcLen - (UINT32)(pucPos - pucSrc))) != NULL) {
        if (strncmp(pucTmp, pucSub, uSubLen) == 0) {
            return pucTmp;
        } else {
            pucPos = pucTmp + 1;
        }
    }

    return NULL;
}

s32 DPI_StrReplace(UCHAR *pcDst, UCHAR * pcSrc, UCHAR *pcFind, UCHAR *pcRepalce, UINT32 uLen)
{
    UCHAR *pcOut = NULL;
    UCHAR *pcIn = NULL;
    UCHAR *pcStrFind =NULL;
    UINT32 uStrLen = 0;
    UINT32 uSrcLen = 0;
    UINT32 uRepalceLen = 0;
    UINT32 uFindLen = 0;
	UINT32 uOffset = 0;

    if (NULL == pcSrc || NULL == pcFind || NULL == pcRepalce)
    {
        return HS_ERR;
    }

    pcIn = pcSrc;
	pcOut = pcDst;
    uSrcLen = strlen(pcIn);
	uFindLen = strlen(pcFind);
	uRepalceLen = strlen(pcRepalce);

    if (uSrcLen < uLen)
    {
        return HS_ERR;
    }

    pcStrFind = DPI_StrnStr(pcIn, pcFind, uLen);
	uOffset = (pcIn + uSrcLen) - pcStrFind;
	if (uOffset < 1)
	{
		return HS_ERR;
	}

    if (NULL != pcStrFind)
    {
		uStrLen = (UINT32)(pcStrFind - pcIn);
		if (0 != uStrLen)
		{
			memcpy(pcOut, pcIn, uStrLen);
			memcpy(pcOut + uStrLen, pcRepalce, uRepalceLen);
			pcIn = pcStrFind + uFindLen;
			pcOut = pcOut + uStrLen + uRepalceLen;
			uLen = uLen - uStrLen - uFindLen;
			memcpy(pcOut, pcIn, uLen);
            *(pcOut + uLen) = '\0';
		}
    }else
    {
       memcpy(pcOut, pcIn, uLen); 
    }

    return HS_OK;;
}

static int dpi_account_check_number(char *data, int length)
{
    int index = 0;
    char temp = '\0';
    
    if (data == NULL || length <= 0) {
        return HS_ERR;
    }
    
    for (index = 0; index < length; index++) {
        temp = *(data + index);
        if (temp < '0' || temp > '9') {
            return HS_ERR;
        }
    }

    return HS_OK;
}

static int dpi_account_check_emailAddress(char *data, int length)
{
    int index = 0;
    int count = 0;
    char temp = '\0';

    /*长度为3: x@y */
    if (data == NULL || length < 3) {
        return HS_ERR;
    }
   
    if (strstr(data, "@") == NULL) {
        return HS_ERR;
    }

    /*除@之外,可为英文字母、数字、下划线、减号、点*/
    for (index = 0; index < length; index++) {
        temp = *(data + index);
        if (temp >= '0' && temp <= '9' ) {
            ;
        }
        else if (temp >= 'a' && temp <= 'z') {
            ;
        }
        else if (temp >= 'A' && temp <= 'Z') {
            ;
        }
        else if (temp == '-' || temp == '_' || temp == '.') {
            ;
        }
        else if ((temp == '@') && (index != 0) && (index != length - 1)) {
            count++;
        }
        else {
            return HS_ERR;
        }
    }

    if (count > 1) {
        return HS_ERR;
    }

    return HS_OK;
}

static int QQ_Process(HS_CTX_S *pstCtx, HS_PKT_DETAIL_S *pstDetail, void *priv)
{
    u32 probe_count;
    u32 app_id;
    u32 qq_account;
    char qq_account_buff[16];

    app_id = atomic_read(&pstCtx->appid);
    probe_count = pstDetail->uProcCount;

    /* probe_count limitation*/
    if (app_id != g_appid_qq_chat || probe_count > 10) {
        return HS_OK;
    }

    HS_PLUGIN_DEAL_STAT(HS_PLUGIN_ACCOUNT);
    if (pstDetail->tuple.protocol == UDP_PROTOCOL) {
        if (pstDetail->data[3] == '\x08' && pstDetail->data[4] == '\x25') {
            memcpy((CHAR *)&qq_account, pstDetail->data + 7, 4);
            goto QQ_LOGIN;
        }    
        else
        {       
            if (pstDetail->data[2] == '\x07' && pstDetail->data[3] == '\x03') 
            {
                memcpy((CHAR *)&qq_account, pstDetail->data + 7, 4);
                goto QQ_LOGIN;
            }
            else 
            {
                if(pstDetail->data[0] == '\x3e' )
                {
                    return HS_OK;
                }          
                memcpy((CHAR *)&qq_account, pstDetail->data + 7, 4);
                goto QQ_SENDMSG;
            }
        }
    }
    else {
        return HS_OK;
    }

QQ_LOGIN:
    qq_account = ntohl(qq_account);
    HS_WRITE_LOCK_CTX(pstCtx);
    pstCtx->pstAccount = hs_malloc(sizeof(struct app_account));
    if (pstCtx->pstAccount != NULL)
    {
        memset(pstCtx->pstAccount, 0, sizeof(struct app_account));
        pstCtx->pstAccount->account_type = ACCOUNT_QQ_CHAT;
        sprintf(pstCtx->pstAccount->account_buff, "%u", qq_account);
		HS_PLUGIN_IDENTIFY_STAT(HS_PLUGIN_ACCOUNT);
    }

    HS_WRITE_UNLOCK_CTX(pstCtx);

    return HS_OK;
    
QQ_SENDMSG:
    qq_account = ntohl(qq_account);
    HS_WRITE_LOCK_CTX(pstCtx);
    pstCtx->pstAccount = hs_malloc(sizeof(struct app_account));
    if (pstCtx->pstAccount != NULL)
    {
        memset(pstCtx->pstAccount, 0, sizeof(struct app_account));
        pstCtx->pstAccount->account_type = ACCOUNT_QQ_CHAT_SENDMSG;
        sprintf(pstCtx->pstAccount->account_buff, "%u", qq_account);
        HS_PLUGIN_IDENTIFY_STAT(HS_PLUGIN_ACCOUNT);
    }

    HS_WRITE_UNLOCK_CTX(pstCtx);

    return HS_OK;
}

static int QQ_Init(void)
{
    g_appid_qq_chat = GetAppId(DPI_QQ_CHAT);

    if (IS_UNKNOWN_ID(g_appid_qq_chat)) {
        HS_INFO("account cann't find app(%s)\n", DPI_QQ_CHAT);
        return HS_ERR;
    }

    return ACCOUNT_CreateHook(ACCOUNT_HOOK_QQ, QQ_Process, NULL, NULL);
}

static int QQ_Mobile_Process(HS_CTX_S *pstCtx, HS_PKT_DETAIL_S *pstDetail, void *priv)
{
    u32  probe_count;
    u32  app_id;
    u32  qq_account;
    u32  len_data = 0;
    s32  index = 0;
    char buff[16];
    u8   flag = 0;
    u8   len = 0;

    app_id = atomic_read(&pstCtx->appid);
    
    if (MASK_VERSION(app_id) != MASK_VERSION(g_appid_qq_chat_mobile)) {
        return HS_OK;
    }
    
    HS_PLUGIN_SET_MARKED(pstCtx,HS_HOOK_POST_DPI, HS_PLUGIN_ACCOUNT);
    HS_PLUGIN_DEAL_STAT(HS_PLUGIN_ACCOUNT);
    if (pstDetail->tuple.protocol != TCP_PROTOCOL) {
        return HS_OK;
    }

    len_data = pstDetail->length;
    if (len_data <= 5) {
        return HS_OK;
    }

    //find number string
    for (index = 1; index < (len_data-5); index++) {
        if (HS_OK == dpi_account_check_number(pstDetail->data+index, 5)) {
            len = *(pstDetail->data + index - 1);
            //margin is 4, min len is 5, max len is 15
            if ((len < (4 + 5)) || (len > (4 + 15))) { 
                continue;
            }

            len = len - 4;
            if (len >= (len_data - index)) {
                continue;
            }

            if (HS_OK == dpi_account_check_number(pstDetail->data+index, len)) {
                flag = 1;
                memset(buff, 0, 16);
                memcpy(buff, pstDetail->data+index, len);
                break;
            }
        }
    }

    //account not found
    if (flag == 0) {
        return HS_OK;
    }

    HS_WRITE_LOCK_CTX(pstCtx);
    if (NULL == pstCtx->pstAccount)
    {
        pstCtx->pstAccount = hs_malloc(sizeof(struct app_account));
        if (pstCtx->pstAccount != NULL)
        {
            memset(pstCtx->pstAccount, 0, sizeof(struct app_account));
            pstCtx->pstAccount->account_type = ACCOUNT_QQ_CHAT;
            memset(pstCtx->pstAccount->account_buff, 0, ACCOUNT_MAX_LEN);
            memcpy(pstCtx->pstAccount->account_buff, buff, len);
    		HS_PLUGIN_IDENTIFY_STAT(HS_PLUGIN_ACCOUNT);
        } 
    }
    else
    {
        if (0 != strncmp(pstCtx->pstAccount->account_buff, buff, ACCOUNT_MAX_LEN-1))
        {
            memset(pstCtx->pstAccount->account_buff, 0, ACCOUNT_MAX_LEN);
            memcpy(pstCtx->pstAccount->account_buff, buff, len);
            pstCtx->pstAccount->flag = ACCOUNT_GET_OTHER;
        }   
    }
  
    HS_PLUGIN_SET_MARKED(pstCtx,HS_HOOK_POST_DPI, HS_PLUGIN_ACCOUNT);

    HS_WRITE_UNLOCK_CTX(pstCtx);

    return HS_OK;
    
}

static int QQ_Mobile_Init(void)
{
    g_appid_qq_chat_mobile  = GetAppId(DPI_QQ_CHAT_MOBILE);

    if (IS_UNKNOWN_ID(g_appid_qq_chat_mobile)) {
        HS_INFO("account cann't find app(%s)\n", DPI_QQ_CHAT_MOBILE);
        return HS_ERR;
    }

    return ACCOUNT_CreateHook(ACCOUNT_HOOK_QQ_MOBILE, QQ_Mobile_Process, NULL, NULL);
}

static int Weixin_Mobile_Process_2(HS_CTX_S *pstCtx, HS_PKT_DETAIL_S *pstDetail, void *priv)
{
	u32  app_id;
	u32  len = 0;
	u8  *pState = 0;
	u32	 uid = 0;
	
	app_id = atomic_read(&pstCtx->appid);  
    
    if (app_id != g_appid_weixin_mobile_2) {
        return HS_OK;
    }

	len = pstDetail->length;

	pState = DPI_StrnStr(pstDetail->data, "\r\n\r\n", len);
	if (pState == NULL)
	{
		return HS_OK;
	}
	pState += strlen("\r\n\r\n");

	if((pState + 11) > (pstDetail->data + len))
	{
		return HS_OK;
	}

	uid = pState[7] * 16*16*16*16*16*16 + pState[8] * 16*16*16*16 + pState[9] * 16*16 + pState[10];

	HS_WRITE_LOCK_CTX(pstCtx);

	if (pstCtx ->pstAccount == NULL)
	{
	    pstCtx->pstAccount = hs_malloc(sizeof(struct app_account));
	    if (pstCtx->pstAccount == NULL)
	    {
	        return HS_OK;
	        
	    }
		memset(pstCtx->pstAccount, 0, sizeof(struct app_account));
	}

	pstCtx->pstAccount->account_type = ACCOUNT_WEIXIN_MOBILE;
	sprintf(pstCtx->pstAccount->account_buff, "%d", uid);

    HS_WRITE_UNLOCK_CTX(pstCtx);	
	
}

static int Weixin_Mobile_Process(HS_CTX_S *pstCtx, HS_PKT_DETAIL_S *pstDetail, void *priv)
{
    u32  probe_count;
    u32  account;
    u32  app_id;
    u32  len_data = 0;
    s32  index = 0;
    char buff[16];
    u8   flag = 0;
    u8   len = 0;

    UCHAR *data = NULL;

    app_id = atomic_read(&pstCtx->appid);  
    
    if (app_id != g_appid_weixin_mobile) {
        return HS_OK;
    }
    
    HS_PLUGIN_DEAL_STAT(HS_PLUGIN_ACCOUNT);

    len_data = pstDetail->length;
    if (len_data < 25) {
        return HS_OK;
    }

    data = pstDetail->data;
    if (NULL == data) {
        return HS_OK;
    }
    
    // 00 00 08 38 00 10 00 01  00 00 00 fe 00 00 00 02
    // a2 9f 26 02 05 33 34 4d  cc fe c0 02 08 02 d1 4c
    if ((data[18] == 0x26) && (data[19] < 0x05) && (data[20] == 0x05)) {
        memcpy((UCHAR *)&account, data + 21, 4);
    }
    else {
        return HS_OK;
    }

    HS_WRITE_LOCK_CTX(pstCtx);
    pstCtx->pstAccount = hs_malloc(sizeof(struct app_account));
    if (pstCtx->pstAccount != NULL)
    {
        memset(pstCtx->pstAccount, 0, sizeof(struct app_account));
        pstCtx->pstAccount->account_type = ACCOUNT_WEIXIN_MOBILE;
        sprintf(pstCtx->pstAccount->account_buff, "%u", account);
		HS_PLUGIN_IDENTIFY_STAT(HS_PLUGIN_ACCOUNT);
    }

    HS_WRITE_UNLOCK_CTX(pstCtx);

    return HS_OK;
    
}

static int Weixin_Mobile_Init(void)
{
    g_appid_weixin_mobile = GetAppId(DPI_WEIXIN_MOBILE);

    if (IS_UNKNOWN_ID(g_appid_weixin_mobile)) {
        HS_INFO("account cann't find app(%s)\n", DPI_WEIXIN_MOBILE);
        return HS_ERR;
    }

    return ACCOUNT_CreateHook(ACCOUNT_HOOK_WEIXIN_MOBILE, Weixin_Mobile_Process, NULL, NULL);
}

static int Weixin_Mobile_Init_2(void)
{
    g_appid_weixin_mobile_2 = GetAppId(DPI_WEIXIN_MOBILE_2);

    if (IS_UNKNOWN_ID(g_appid_weixin_mobile_2)) {
        HS_INFO("account cann't find app(%s)\n", DPI_WEIXIN_MOBILE_2);
        return HS_ERR;
    }

    return ACCOUNT_CreateHook(ACCOUNT_HOOK_WEIXIN_MOBILE_2, Weixin_Mobile_Process_2, NULL, NULL);
}




/*新浪微博账户:手机号、邮箱*/
static int SinaWeibo_Process(HS_CTX_S *pstCtx, HS_PKT_DETAIL_S *pstDetail, void *priv)
{
    INT32  account_len = 0;
    UINT32 app_id;
    INT32  data_len = 0;
	INT32  len_start = 0;
    char  *start = NULL;
	char  *data = NULL;
    INT32  index = 0;
    INT32  index2 = 0;
	INT32  ret_1 = 0;
	INT32  ret_2 = 0;

    if (pstCtx->pstAccount != NULL) {
        return HS_OK;
    }

    app_id = atomic_read(&pstCtx->appid);
    if (app_id != g_appid_sina_weibo) {
        return HS_OK;
    }

    HS_PLUGIN_DEAL_STAT(HS_PLUGIN_ACCOUNT);

	data = pstDetail->data;
	data_len = pstDetail->length;
	len_start = strlen("un=");
    for (index = 0; index < data_len-len_start; index++) {
		if ((*(data+index) == 'u') && (*(data+index+1) == 'n')) {
			if (0 != strncmp(data+index, "un=", len_start)) {
            	continue;
			}

			start = data + index;
			for (index2 = index + len_start; index2 < data_len; index2++) {
				if( *(data+index2) == ';' ) {
					account_len = index2 - (index + len_start);
					goto FOUND;
				}
			}
		} 
    }

    return HS_OK;

FOUND:

    if (account_len <= 0 || account_len >= ACCOUNT_MAX_LEN) {
        return HS_OK;
    }

    /*账户信息合法性检查*/
    ret_1 = dpi_account_check_number(start+len_start, account_len);
    ret_2 = dpi_account_check_emailAddress(start+len_start, account_len);
    if (ret_1 == HS_ERR && ret_2 == HS_ERR) {
        return HS_OK;
    }

    HS_WRITE_LOCK_CTX(pstCtx);
    pstCtx->pstAccount = hs_malloc(sizeof(struct app_account));
    if (pstCtx->pstAccount != NULL)
    {
        memset(pstCtx->pstAccount, 0, sizeof(struct app_account));
        pstCtx->pstAccount->account_type = ACCOUNT_SINA_WEI_BO;
        memcpy(pstCtx->pstAccount->account_buff, start+len_start, account_len);
		HS_PLUGIN_IDENTIFY_STAT(HS_PLUGIN_ACCOUNT);
    }

    HS_WRITE_UNLOCK_CTX(pstCtx);
    
    return HS_OK;
}

static int SinaWeibo_Init(void)
{
    g_appid_sina_weibo = GetAppId(DPI_SINA_WEIBO_LOGIN);
    if (IS_UNKNOWN_ID(g_appid_sina_weibo)) {
        HS_INFO("account cann't find app(%s)\n", DPI_SINA_WEIBO_LOGIN);
        return HS_ERR;
    }

    return ACCOUNT_CreateHook(ACCOUNT_HOOK_SINA_WEI_BO, SinaWeibo_Process, NULL, NULL);
}


/*阿里旺旺账户: 会员名、手机号、邮箱，可为中文字符*/
static int WangWang_Process(HS_CTX_S *pstCtx, HS_PKT_DETAIL_S *pstDetail, void *priv)
{
    UINT32 app_id;
	UINT32 probe_count = 0;
    INT32  data_len = 0;
	INT32  len_start = 0;
    INT32  account_len = 0;
    INT32  index = 0;
    char  *start = NULL;
	char  *data = NULL;

    if (pstCtx->pstAccount != NULL) {
        return HS_OK;
    }

	probe_count = pstDetail->uProcCount;
	if (probe_count > 10)
	{
		HS_PLUGIN_SET_UNMARKED(pstCtx, HS_HOOK_POST_DPI, HS_PLUGIN_ACCOUNT);
        return HS_OK;
	}

    app_id = atomic_read(&pstCtx->appid);
    if (MASK_VERSION(app_id) != g_appid_wang_wang_chat) {
        return HS_OK;
    }
	
    HS_PLUGIN_DEAL_STAT(HS_PLUGIN_ACCOUNT);
		
	/* 标志字符串前的1 个字符为长度 */
	data = pstDetail->data;
	data_len = pstDetail->length;
	len_start = strlen("cntaobao");
    for (index = 0; index < data_len-len_start; index++) {
		if ((*(data+index) == 'c') && (*(data+index+1) == 'n')) {
			if ( 0 == strncmp(data+index, "cntaobao", len_start)) {
				start = data + index;
            	goto FOUND;
			}
		} 
    }

    HS_PLUGIN_SET_MARKED(pstCtx, HS_HOOK_POST_DPI, HS_PLUGIN_ACCOUNT);
    
    return HS_OK;
    
FOUND:      
    account_len = *(start - 1) - len_start;
    if (account_len <= 0 || account_len >= ACCOUNT_MAX_LEN) {
        return HS_OK;
    }

    HS_WRITE_LOCK_CTX(pstCtx);
    pstCtx->pstAccount = hs_malloc(sizeof(struct app_account));
    if (pstCtx->pstAccount != NULL)
    {
        memset(pstCtx->pstAccount, 0, sizeof(struct app_account));
        pstCtx->pstAccount->account_type = ACCOUNT_WANG_WANG_CHAT;
        memcpy(pstCtx->pstAccount->account_buff, start + len_start, account_len);
		HS_PLUGIN_SET_UNMARKED(pstCtx, HS_HOOK_POST_DPI, HS_PLUGIN_ACCOUNT);
		HS_PLUGIN_IDENTIFY_STAT(HS_PLUGIN_ACCOUNT);
    }

    HS_WRITE_UNLOCK_CTX(pstCtx);

    return HS_OK;
}

static int WangWangChat_Init(void)
{
    g_appid_wang_wang_chat = GetAppId(DPI_WANG_WANG_CHAT);
    if (IS_UNKNOWN_ID(g_appid_wang_wang_chat)) {
        HS_INFO("account cann't find app(%s)\n", DPI_WANG_WANG_CHAT);
        return HS_ERR;
    }

    return ACCOUNT_CreateHook(ACCOUNT_HOOK_WANG_WANG, WangWang_Process, NULL, NULL);
}


/*飞信聊天账户: 必须为数字*/
static int Fetion_Process(HS_CTX_S *pstCtx, HS_PKT_DETAIL_S *pstDetail, void *priv)
{
    INT32  account_len = 0;
    UINT32 app_id = 0;
    INT32  data_len = 0;
	INT32  len_start = 0;
    char  *start = NULL;
	char  *data = NULL;
    INT32  index = 0;
	INT32  index2 = 0;

    if (pstCtx->pstAccount != NULL) {
        return HS_OK;
    }

    app_id = atomic_read(&pstCtx->appid);
    if (app_id != g_appid_fetion) {
        return HS_OK;
    }
	
    HS_PLUGIN_DEAL_STAT(HS_PLUGIN_ACCOUNT);

	data = pstDetail->data;
	data_len = pstDetail->length;
	len_start = strlen("F:");
    for (index = 0; index < data_len-len_start; index++) {
		if ((*(data+index) == 'F') && (*(data+index+1) == ':')) {
			start = data + index + 1;
			for (index2 = index+len_start; index2 < data_len; index2++) {
				if (*(data+index2) == '\r') {
					account_len = index2 - (index + 1 + len_start);
					goto FOUND;
				}
			}
		} 
    }
    
    return HS_OK;
    
FOUND:

    if (account_len <= 0 || account_len >= ACCOUNT_MAX_LEN) {
        return HS_OK;;
    }

    /*账户信息合法性检查*/
    if (HS_ERR == dpi_account_check_number(start+len_start, account_len)) {
        return HS_OK;
    }
    
    HS_WRITE_LOCK_CTX(pstCtx);
    pstCtx->pstAccount = hs_malloc(sizeof(struct app_account));
    if (pstCtx->pstAccount != NULL)
    {
        memset(pstCtx->pstAccount, 0, sizeof(struct app_account));
        pstCtx->pstAccount->account_type = ACCOUNT_FETION;
        memcpy(pstCtx->pstAccount->account_buff, start+len_start, account_len);
		HS_PLUGIN_IDENTIFY_STAT(HS_PLUGIN_ACCOUNT);
    }
    HS_WRITE_UNLOCK_CTX(pstCtx);
    
    return HS_OK;
}


static int Fetion_Init(void)
{
    g_appid_fetion = GetAppId(DPI_FETION_LOGIN);
    if (IS_UNKNOWN_ID(g_appid_fetion)) {
        HS_INFO("account cann't find app(%s)\n", DPI_FETION_LOGIN);
        return HS_ERR;
    }

    return ACCOUNT_CreateHook(ACCOUNT_HOOK_FETION, Fetion_Process, NULL, NULL);
}

static int BaiduLogin_Process(HS_CTX_S *pstCtx, HS_PKT_DETAIL_S *pstDetail, void *priv)
{
    INT32  account_len = 0;
    UINT32 app_id;
    INT32  data_len = 0;
	INT32  len_start = 0;
    INT32  index = 0;
    INT32  index2 = 0;
	UCHAR *data = NULL;
	UCHAR *start = NULL;
	
	DPI_ACCOUNT_E  type = ACCOUNT_MAX;

    if (pstCtx->pstAccount != NULL) {
        return HS_OK;
    }
	
    app_id = atomic_read(&pstCtx->appid);
	if (app_id != g_appid_baidu_login) {
		return HS_OK;
	}
    
    HS_PLUGIN_DEAL_STAT(HS_PLUGIN_ACCOUNT);
	//mail:    userName=qustlibin500%40126.com&
	//phone: userName=15022601767&
	data = pstDetail->data;
	data_len = pstDetail->length;
	account_len = 0;
	len_start = strlen("userName=");
    for (index = 0; index < data_len-len_start; index++) {
		if ((*(data+index) == 'u') && (*(data+index+1) == 's')) {
			if ( 0 != strncmp(data+index, "userName=", len_start)) {
            	continue;
			}

			start = data + index + len_start + 1;
			for (index2 = index + len_start + 1; index2 < data_len; index2++) {
				if (*(data+index2) == '&' ) {
					account_len = index2 - (index + len_start + 1);
					goto FOUND;
				}
			}
		} 
    }
   
	return HS_OK;
	
FOUND:

	if (account_len <= 0 || account_len >= ACCOUNT_MAX_LEN) {
        return HS_OK;
    }

	HS_WRITE_LOCK_CTX(pstCtx);
    pstCtx->pstAccount = hs_malloc(sizeof(struct app_account));
    if (pstCtx->pstAccount != NULL)
    {
        memset(pstCtx->pstAccount, 0, sizeof(struct app_account));
        pstCtx->pstAccount->account_type = ACCOUNT_BAIDU_LOGIN;
        strncpy(pstCtx->pstAccount->account_buff, start, account_len);

		/* 替换%40为@符号 */
        for (index = 0; index < account_len - 3; index++) {
			if (0 == strncmp(pstCtx->pstAccount->account_buff+index, "%40", 3)) {
            	for (index2 = index; index2 < account_len; index2++) {
					pstCtx->pstAccount->account_buff[index2] = pstCtx->pstAccount->account_buff[index2+3];
            	}
				pstCtx->pstAccount->account_buff[account_len-3] = 0;
				break;
			}
        }
        HS_PLUGIN_IDENTIFY_STAT(HS_PLUGIN_ACCOUNT);
    }
	HS_WRITE_UNLOCK_CTX(pstCtx);
	
    return HS_OK;
}

static int BaiduLogin_Init(void)
{
    g_appid_baidu_login = GetAppId(DPI_BAIDU_LOGIN);
	
    if (IS_UNKNOWN_ID(g_appid_baidu_login)) {
        HS_INFO("account cann't find app(%s)\n", DPI_BAIDU_LOGIN);
        return HS_ERR;
    }

    return ACCOUNT_CreateHook(ACCOUNT_HOOK_BAIDU, BaiduLogin_Process, NULL, NULL);
}

static int Wangyi126mail_Process(HS_CTX_S *pstCtx, HS_PKT_DETAIL_S *pstDetail, void *priv)
{
    INT32  account_len = 0;
    UINT32 app_id;
    INT32  data_len = 0;
	INT32  len_start = 0;
    INT32  index = 0;
    INT32  index2 = 0;
	UCHAR *data = NULL;
	UCHAR *start = NULL;
	
	DPI_ACCOUNT_E  type = ACCOUNT_MAX;

    if (pstCtx->pstAccount != NULL) {
        return HS_OK;
    }
	
    HS_PLUGIN_DEAL_STAT(HS_PLUGIN_ACCOUNT);
    app_id = atomic_read(&pstCtx->appid);
	data = pstDetail->data;
	data_len = pstDetail->length;
	account_len = 0;
	//login: uid=qustlibin500@126.com;
    if ( app_id == g_appid_126mail_login ) { 
		len_start = strlen("uid=");
	    for (index = 0; index < data_len-len_start; index++) {
			if ((*(data+index) == 'u') && (*(data+index+1) == 'i')) {
				if ( 0 != strncmp(data+index, "uid=", len_start)) {
                	continue;
				}

				start = data + index + len_start;
				for (index2 = index + len_start + 1; index2 < data_len; index2++) {
					if(*(data+index2) == '&' ) {
						type = ACCOUNT_126MAIL_LOGIN;
						account_len = index2 - (index + len_start);
						goto FOUND;
					}
				}
			} 
	    }
    }
	//send mail: nts_mail_user=qustlibin500:-1:1;
    else if (app_id == g_appid_126mail_send) {
		len_start = strlen("nts_mail_user=");
	    for (index = 0; index < data_len-len_start; index++) {
			if ((*(data+index) == 'n') && (*(data+index+1) == 't')) {
				if (0 != strncmp(data+index, "nts_mail_user=", len_start)) {
                	continue;
				}

				start = data + index + len_start;
				for (index2 = index + len_start + 1; index2 < data_len; index2++) {
					if( *(data+index2) == ':' ) {
						type = ACCOUNT_126MAIL_SEND;
						account_len = index2 - (index + len_start);
						if (account_len > ACCOUNT_MAX_LEN - 8)
						{
                            return HS_OK;
						}
						goto FOUND;
					}
				}
			} 
	    }
    }

	return HS_OK;
	
FOUND:
	if (account_len <= 0 || account_len >= ACCOUNT_MAX_LEN) {
        return HS_OK;
    }

	HS_WRITE_LOCK_CTX(pstCtx);
    pstCtx->pstAccount = hs_malloc(sizeof(struct app_account));
    if (pstCtx->pstAccount != NULL)
    {
        memset(pstCtx->pstAccount, 0, sizeof(struct app_account));
        pstCtx->pstAccount->account_type = type;
        strncpy(pstCtx->pstAccount->account_buff, start, account_len);
		if (ACCOUNT_126MAIL_SEND == type)
		{
			strncat(pstCtx->pstAccount->account_buff, "@126.com", 8);
		}
		HS_PLUGIN_IDENTIFY_STAT(HS_PLUGIN_ACCOUNT);
    }
	HS_WRITE_UNLOCK_CTX(pstCtx);
	
    return HS_OK;
}

static int Wangyi126main_Init(void)
{
    g_appid_126mail_login = GetAppId(DPI_126MAIL_LOGIN);
	g_appid_126mail_send = GetAppId(DPI_126MAIL_SEND);
	
    if (IS_UNKNOWN_ID(g_appid_126mail_login) || IS_UNKNOWN_ID(g_appid_126mail_send)) {
        HS_INFO("account cann't find app(%s) or app(%s)\n", DPI_126MAIL_LOGIN, DPI_126MAIL_SEND);
        
        return HS_ERR;
    }

    return ACCOUNT_CreateHook(ACCOUNT_HOOK_126MAIL, Wangyi126mail_Process, NULL, NULL);
}

static int Wangyi163mail_Process(HS_CTX_S *pstCtx, HS_PKT_DETAIL_S *pstDetail, void *priv)
{
    INT32  account_len = 0;
    UINT32 app_id;
    INT32  data_len = 0;
	INT32  len_start = 0;
    INT32  index = 0;
    INT32  index2 = 0;
	UCHAR *data = NULL;
	UCHAR *start = NULL;

	DPI_ACCOUNT_E  type = ACCOUNT_MAX;

    if (pstCtx->pstAccount != NULL) {
        return HS_OK;
    }
	
    HS_PLUGIN_DEAL_STAT(HS_PLUGIN_ACCOUNT);
    app_id = atomic_read(&pstCtx->appid);
	data = pstDetail->data;
	data_len = pstDetail->length;
	account_len = 0;
	//login: mail_uid=qustlibin500@163.com;
    if ( app_id == g_appid_163mail_login ) { 
		len_start = strlen("uid=");
	    for (index = 0; index < data_len-len_start; index++) {
			if ((*(data+index) == 'u') && (*(data+index+1) == 'i')) {
				if (0 != strncmp(data+index, "uid=", len_start)) {
                	continue;
				}

				start = data + index + len_start;
				for (index2 = index + len_start + 1; index2 < data_len; index2++) {
					if(*(data+index2) == '&' ) {
						type = ACCOUNT_163MAIL_LOGIN;
						account_len = index2 - (index + len_start);
						goto FOUND;
					}
				}
			} 
	    }
    }
	//send mail: nts_mail_user=qustlibin500:-1:1;
    else if (app_id == g_appid_163mail_send) {
		len_start = strlen("nts_mail_user=");
	    for (index = 0; index < data_len-len_start; index++) {
			if ((*(data+index) == 'n') && (*(data+index+1) == 't')) {
				if ( 0 != strncmp(data+index, "nts_mail_user=", len_start)) {
                	continue;
				}

				start = data + index + len_start;
				for (index2 = index + len_start + 1; index2 < data_len; index2++) {
					if(*(data+index2) == ':' ) {
						type = ACCOUNT_163MAIL_SEND;
						account_len = index2 - (index + len_start);
						if (account_len > ACCOUNT_MAX_LEN - 8)
						goto FOUND;
					}
				}
			} 
	    }
    }

	return HS_OK;
	
FOUND:
	if (account_len <= 0 || account_len >= ACCOUNT_MAX_LEN) {
        return HS_OK;
    }

	HS_WRITE_LOCK_CTX(pstCtx);
    pstCtx->pstAccount = hs_malloc(sizeof(struct app_account));
    if (pstCtx->pstAccount != NULL)
    {
        memset(pstCtx->pstAccount, 0, sizeof(struct app_account));
        pstCtx->pstAccount->account_type = type;
        strncpy(pstCtx->pstAccount->account_buff, start, account_len);
		if (ACCOUNT_163MAIL_SEND == type)
		{
			strncat(pstCtx->pstAccount->account_buff, "@163.com", 8);
		}
        HS_PLUGIN_IDENTIFY_STAT(HS_PLUGIN_ACCOUNT);
    }
	HS_WRITE_UNLOCK_CTX(pstCtx);
	
    return HS_OK;
}

static int Wangyi163main_Init(void)
{
    g_appid_163mail_login = GetAppId(DPI_163MAIL_LOGIN);
	g_appid_163mail_send = GetAppId(DPI_163MAIL_SEND);
	
    if (IS_UNKNOWN_ID(g_appid_163mail_login) || IS_UNKNOWN_ID(g_appid_163mail_send)) {
        HS_INFO("account cann't find app(%s) or app(%s)\n", DPI_163MAIL_LOGIN, DPI_163MAIL_SEND);
        return HS_ERR;
    }

    return ACCOUNT_CreateHook(ACCOUNT_HOOK_163MAIL, Wangyi163mail_Process, NULL, NULL);
}

static int WangyiweiboLogin_Process(HS_CTX_S *pstCtx, HS_PKT_DETAIL_S *pstDetail, void *priv)
{
    INT32  account_len = 0;
    UINT32 app_id;
    INT32  data_len = 0;
    INT32  len_start = 0;
    INT32  index = 0;
    INT32  index2 = 0;
    UCHAR *data = NULL;
    UCHAR *start = NULL;

    DPI_ACCOUNT_E  type = ACCOUNT_MAX;

    if (pstCtx->pstAccount != NULL) 
    {
        return HS_OK;
    }

    app_id = atomic_read(&pstCtx->appid);
    if (app_id != g_appid_wangyiweibo_login)
    {
    	return HS_OK;
    }

    HS_PLUGIN_DEAL_STAT(HS_PLUGIN_ACCOUNT);

    //login:    username=395120787@qq.com HTTP/1.1

    data = pstDetail->data;
    data_len = pstDetail->length;
    account_len = 0;
    len_start = strlen("username=");
    for (index = 0; index < data_len-len_start; index++) 
    {
        if ((*(data+index) == 'u') && (*(data+index+1) == 's'))
        {
            if (0 != strncmp(data+index, "username=", len_start))
            {
                continue;
            }

            start = data + index + len_start;
            for (index2 = index + len_start + 1; index2 < data_len; index2++)
            {
                if(*(data+index2) == ' ' ) 
                {
                    type = ACCOUNT_WANGYIWEIBO_LOGIN;
                    account_len = index2 - (index + len_start);
                    goto FOUND;
                }
            }
        } 
    }

return HS_OK;

FOUND:

	if (account_len <= 0 || account_len >= ACCOUNT_MAX_LEN)
	{
	    return HS_OK;
	}

    HS_WRITE_LOCK_CTX(pstCtx);
    pstCtx->pstAccount = hs_malloc(sizeof(struct app_account));
    if (pstCtx->pstAccount != NULL)
    {
        memset(pstCtx->pstAccount, 0, sizeof(struct app_account));
        pstCtx->pstAccount->account_type = type;
        strncpy(pstCtx->pstAccount->account_buff, start, account_len);
        HS_PLUGIN_IDENTIFY_STAT(HS_PLUGIN_ACCOUNT);
    }
    HS_WRITE_UNLOCK_CTX(pstCtx);

return HS_OK;
}

static int WangyiweiboLogin_Init(void)
{
    g_appid_wangyiweibo_login = GetAppId(DPI_WANGYIWEIBO_LOGIN);
	
    if (IS_UNKNOWN_ID(g_appid_wangyiweibo_login)) {
        HS_INFO("account cann't find app(%s)\n", DPI_WANGYIWEIBO_LOGIN);
        return HS_ERR;
    }

    return ACCOUNT_CreateHook(ACCOUNT_HOOK_WANGYI_WEI_BO, WangyiweiboLogin_Process, NULL, NULL);
}

static int DoubanLogin_Process(HS_CTX_S *pstCtx, HS_PKT_DETAIL_S *pstDetail, void *priv)
{
    INT32  account_len = 0;
    UINT32 app_id;
    INT32  data_len = 0;
    INT32  len_start = 0;
    INT32  index = 0;
    INT32  index2 = 0;
    UCHAR *data = NULL;
    UCHAR *start = NULL;

    DPI_ACCOUNT_E  type = ACCOUNT_MAX;

    if (pstCtx->pstAccount != NULL) 
    {
        return HS_OK;
    }

    app_id = atomic_read(&pstCtx->appid);
    if (app_id != g_appid_douban_login)
    {
    	return HS_OK;
    }

    HS_PLUGIN_DEAL_STAT(HS_PLUGIN_ACCOUNT);

    //login:    alias=395120787%40qq.com&

    data = pstDetail->data;
    data_len = pstDetail->length;
    account_len = 0;
    len_start = strlen("alias=");
    for (index = 0; index < data_len-len_start; index++) 
    {
        if ((*(data+index) == 'a') && (*(data+index+1) == 'l'))
        {
            if (0 != strncmp(data+index, "alias=", len_start))
            {
                continue;
            }

            start = data + index + len_start+1 ;
            for (index2 = index + len_start +1; index2 < data_len; index2++)
            {
                if(*(data+index2) == '&' ) 
                {
                    type = ACCOUNT_DOUBAN_LOGIN;
                    account_len = index2 - (index + len_start+1 );
                    goto FOUND;
                }
            }
        } 
    }

    return HS_OK;

FOUND:

	if (account_len <= 0 || account_len >= ACCOUNT_MAX_LEN)
	{
	    return HS_OK;
	}

    HS_WRITE_LOCK_CTX(pstCtx);
    pstCtx->pstAccount = hs_malloc(sizeof(struct app_account));
    if (pstCtx->pstAccount != NULL)
    {
        memset(pstCtx->pstAccount, 0, sizeof(struct app_account));
        pstCtx->pstAccount->account_type = type;
        strncpy(pstCtx->pstAccount->account_buff, start, account_len);
        DPI_StrReplace(pstCtx->pstAccount->account_buff,pstCtx->pstAccount->account_buff, "%40", "@", account_len);
        HS_PLUGIN_IDENTIFY_STAT(HS_PLUGIN_ACCOUNT);
    }
    HS_WRITE_UNLOCK_CTX(pstCtx);

    return HS_OK;
}

static int DoubanLogin_Init(void)
{
    g_appid_douban_login = GetAppId(DPI_DOUBAN_LOGIN);
	
    if (IS_UNKNOWN_ID(g_appid_douban_login)) {
        HS_INFO("account cann't find app(%s)\n", DPI_DOUBAN_LOGIN);
        return HS_ERR;
    }

    return ACCOUNT_CreateHook(ACCOUNT_HOOK_DOUBAN, DoubanLogin_Process, NULL, NULL);
}

/*smtp 账号仅为邮箱地址*/
static int SMTP_Process(HS_CTX_S *pstCtx, HS_PKT_DETAIL_S *pstDetail, void *priv)
{	
    INT32 index = 0;
    INT32 iRet = 0;
    INT32 account_len = 0;
	UINT32 offset = 0;
    UINT32 data_len = 0;
    UINT32 app_id = 0;
    char *start_ptr = NULL;
    char *start = NULL;
    char *start_1 = NULL;
    char *end_ptr = NULL;
    char *end_1 = NULL;
	char *data = NULL;

    //已经提取出了账户信息
    if (pstCtx->pstAccount != NULL) 
	{
        return HS_OK;
    }

    app_id = atomic_read(&pstCtx->appid);
    if (MASK_VERSION(app_id) != g_appid_smtp) 
	{
        return HS_OK;
    }
    
    if (atomic_read(&pstCtx->atProcCount)> ACCOUNT_SACN_SMTPNUM_MAX)
    {
        HS_PLUGIN_SET_UNMARKED(pstCtx, HS_HOOK_POST_DPI, HS_PLUGIN_ACCOUNT);
        return HS_OK;
    }

    HS_PLUGIN_DEAL_STAT(HS_PLUGIN_ACCOUNT);

	data = pstDetail->data;
    data_len = pstDetail->length;

	start_1 = DPI_StrnStr(data, "Mail From:<", data_len);
    if (NULL != start_1)
    {
        goto FOUND;
    }
    
    start_ptr = DPI_StrnStr(data, "MAIL FROM: <", data_len);
    if (start_ptr != NULL) 
    {
        goto FOUND;
    }

    if(HS_PLUGIN_UNMARKED(pstCtx, HS_HOOK_POST_DPI, HS_PLUGIN_ACCOUNT)) 
    {
        HS_PLUGIN_SET_UNMARKED_ALL(pstCtx);
        HS_PLUGIN_SET_MARKED(pstCtx, HS_HOOK_POST_DPI, HS_PLUGIN_ACCOUNT);
    }
    return HS_OK;

FOUND:
    if (NULL != start_1)
    {   
        start_1 = start_1 + strlen("Mail From:<");
        offset = (data + data_len) - start_1;
        if (offset < 1)
    	{
    		return HS_OK;
    	}
	
        end_ptr = DPI_StrnStr(start_1, ">", offset);
    	if (NULL == end_ptr)
    	{
    		return HS_OK;
    	}else 
    	{
            account_len = end_ptr - start_1;
            start = start_1;
            if (account_len >= ACCOUNT_MAX_LEN) 
            {
                account_len = ACCOUNT_MAX_LEN;
            }
    	}
        
    }else if (NULL != start_ptr)
    {
        start_ptr = start_ptr + strlen("MAIL FROM: <");
        offset = (data + data_len) - start_ptr;
    	if (offset < 1)
    	{
    		return HS_OK;
    	}
	
        end_ptr = DPI_StrnStr(start_ptr, ">", offset);
    	if (NULL == end_ptr)
    	{
    		return HS_OK;
    	}else 
    	{
            account_len = end_ptr - start_ptr;
            start = start_ptr;
            if (account_len >= ACCOUNT_MAX_LEN) 
            {
                account_len = ACCOUNT_MAX_LEN;
            }
    	}
    }

#if 0
    /*邮箱合法性检测*/
    iRet = dpi_account_check_emailAddress(start, account_len);
    if (HS_ERR == iRet)
    {
        return HS_ERR;
    }
#endif     
    HS_WRITE_LOCK_CTX(pstCtx);
    pstCtx->pstAccount = hs_malloc(sizeof(struct app_account));
    if (NULL == pstCtx->pstAccount)
    {
        return HS_ERR;
    }
    
    
    if (pstCtx->pstAccount != NULL)
    {
        pstCtx->pstAccount->account_type = ACCOUNT_SMTP;
        if (account_len >= ACCOUNT_MAX_LEN) {
            strncpy(pstCtx->pstAccount->account_buff, start, ACCOUNT_MAX_LEN - 1);
            pstCtx->pstAccount->account_buff[ACCOUNT_MAX_LEN - 1] = '\0';
        } else {
            strncpy(pstCtx->pstAccount->account_buff, start, account_len);
            pstCtx->pstAccount->account_buff[account_len] = '\0';
        }
        HS_PLUGIN_IDENTIFY_STAT(HS_PLUGIN_ACCOUNT);
    }

    HS_PLUGIN_SET_UNMARKED(pstCtx, HS_HOOK_POST_DPI, HS_PLUGIN_ACCOUNT);
    HS_WRITE_UNLOCK_CTX(pstCtx);
    
    return HS_OK;
}

static int SMTP_Init(void)
{
    g_appid_smtp = GetAppId(DPI_SMTP_ACC);
    if (IS_UNKNOWN_ID(g_appid_smtp)) 
    {
        return HS_ERR;
    }

    return ACCOUNT_CreateHook(ACCOUNT_HOOK_SMTP, SMTP_Process, NULL, NULL);
}

/*pop3 账号仅为邮箱地址*/
static int POP3_Process(HS_CTX_S *pstCtx, HS_PKT_DETAIL_S *pstDetail, void *priv)
{
    INT32 index = 0;
    INT32 iRet = 0;
    INT32  account_len = 0;
	UINT32 offset = 0;
    UINT32 app_id = 0;
    UINT32 data_len = 0;
    char *start_ptr = NULL;
    char *end_ptr = NULL;
	char *data = NULL;


    //已经提取出了账户信息
    if (pstCtx->pstAccount != NULL) 
	{
        return HS_OK;
    }
    
    app_id = atomic_read(&pstCtx->appid);
    if (MASK_VERSION(app_id) != g_appid_pop3) 
	{
        return HS_OK;
    }
    
    if (atomic_read(&pstCtx->atProcCount)> ACCOUNT_SACN_POP3NUM_MAX)
    {
        HS_PLUGIN_SET_UNMARKED(pstCtx, HS_HOOK_POST_DPI, HS_PLUGIN_ACCOUNT);
        return HS_OK;
    }

    HS_PLUGIN_DEAL_STAT(HS_PLUGIN_ACCOUNT);

	data = pstDetail->data;
    data_len = pstDetail->length;
	start_ptr = DPI_StrnStr(data, "USER ", data_len);	//QQ、QQ邮箱
    if (NULL != start_ptr) 
	{
        goto FOUND;
    }

    if(HS_PLUGIN_UNMARKED(pstCtx, HS_HOOK_POST_DPI, HS_PLUGIN_ACCOUNT)) 
    {
        HS_PLUGIN_SET_UNMARKED_ALL(pstCtx);
        HS_PLUGIN_SET_MARKED(pstCtx, HS_HOOK_POST_DPI, HS_PLUGIN_ACCOUNT);
    }
    
    return HS_OK;

FOUND:
    start_ptr = start_ptr + strlen("USER ");
	offset = (data + data_len) - start_ptr;
	if (offset < 1)
	{
		return HS_OK;
	}
	
	end_ptr = DPI_StrnStr(start_ptr, "\r\n", offset);
	if (NULL == end_ptr)
	{
		return HS_OK;
	}else {
        account_len = end_ptr - start_ptr;
        if (account_len > ACCOUNT_MAX_LEN - 1) 
        {
            account_len = ACCOUNT_MAX_LEN - 1;
        }
    }

#if 0	
    /*检测邮箱合法性*/
    iRet = dpi_account_check_emailAddress(start_ptr, account_len);
    if (HS_ERR == iRet)
    {
        return HS_ERR;
    }
#endif

    HS_WRITE_LOCK_CTX(pstCtx);
    pstCtx->pstAccount = hs_malloc(sizeof(struct app_account));
    if (NULL == pstCtx->pstAccount)
    {
        return HS_ERR;
    }
    
    memset(pstCtx->pstAccount, 0, sizeof(struct app_account));
    if (pstCtx->pstAccount != NULL)
    {
        pstCtx->pstAccount->account_type = ACCOUNT_SMTP;
        if (account_len >= ACCOUNT_MAX_LEN) {
            strncpy(pstCtx->pstAccount->account_buff, start_ptr, ACCOUNT_MAX_LEN - 1);
            pstCtx->pstAccount->account_buff[ACCOUNT_MAX_LEN - 1] = '\0';
        } else {
            strncpy(pstCtx->pstAccount->account_buff, start_ptr, account_len);
            pstCtx->pstAccount->account_buff[account_len] = '\0';
        }
        HS_PLUGIN_IDENTIFY_STAT(HS_PLUGIN_ACCOUNT);
    }
    
    HS_PLUGIN_SET_UNMARKED(pstCtx, HS_HOOK_POST_DPI, HS_PLUGIN_ACCOUNT);
    HS_WRITE_UNLOCK_CTX(pstCtx);
    
    return HS_OK;
}

static int POP3_Init(void)
{
    g_appid_pop3 = GetAppId(DPI_POP3_ACC);
    if (IS_UNKNOWN_ID(g_appid_pop3)) {
        HS_INFO("account cann't find app(%s)\n", DPI_POP3_ACC);
        return HS_ERR;
    }

    return ACCOUNT_CreateHook(ACCOUNT_HOOK_POP3, POP3_Process, NULL, NULL);
}

static int MAOPU_Process(HS_CTX_S *pstCtx, HS_PKT_DETAIL_S *pstDetail, void *priv)
{
	INT32 ret  = 0;
    INT32 account_len = 0;
	UINT32 va_type = 0;
	UINT32 offset = 0;
    UINT32 app_id;
    UINT32 data_len = 0;
	UINT32 len_start = 0;
    INT32  index = 0;
	UCHAR *data = NULL;
	UCHAR *start = NULL;
	UCHAR *start_1 = NULL;
	UCHAR *start_2 = NULL;
	UCHAR *start_3 = NULL;
	UCHAR *start_gb = NULL;
	UCHAR *end_1 = NULL;
	UCHAR *end_2 = NULL;
	UCHAR *end_3 = NULL;
	//CHAR input[64] = {0};
	CHAR output[ACCOUNT_MAX_LEN + 1] = {0};
	UINT32  output_len = 128 - 1;
	
	DPI_ACCOUNT_E  type = ACCOUNT_MAX;

    if (pstCtx->pstAccount != NULL) 
	{
        return HS_OK;
    }

    HS_PLUGIN_DEAL_STAT(HS_PLUGIN_ACCOUNT);

    app_id = atomic_read(&pstCtx->appid);
	data = pstDetail->data;
	data_len = pstDetail->length;

	if (app_id == g_appid_maopu_login)
	{
		type = ACCOUNT_MAOPU_LOGIN;
		start_1 = DPI_StrnStr(data, "ptui_loginuin=", data_len);	//QQ
		if (NULL != start_1)
		{
			goto FOUND;
		}
        
		start_2 = DPI_StrnStr(data, "loginName=", data_len);		//邮箱
		if (NULL !=  start_2)
		{
			goto FOUND;
		}
        
		start_3 = DPI_StrnStr(data, "_mu=", data_len);	//昵称
		if (NULL != start_3)
		{
			goto FOUND;
		}
	}else if (app_id == g_appid_maopu_browser)
	{	
        type = ACCOUNT_MAOPU_BROWSER;
		start_2 = DPI_StrnStr(data, "loginName=", data_len);		//邮箱
		if (NULL != start_2)
		{
			goto FOUND;
		}
        
		start_3 = DPI_StrnStr(data, "_mu=", data_len);	//昵称
		if (NULL !=  start_3)
		{
			goto FOUND;
		}
	}else 
	{
		return HS_OK;
	}
	
FOUND:
	if (NULL != start_1)
	{
		start_1 = start_1 + strlen("ptui_loginuin=");
		offset = (data + data_len) - start_1;
		if (offset < 1)
		{
			return HS_OK;
		}

		end_1 = DPI_StrnStr(start_1, ";", offset);
		if (NULL == end_1)
		{
			return HS_OK;
		}

		va_type = VA_NUM;
		start = start_1;
		account_len = end_1 - start_1;
		
	}else if (NULL != start_2)
	{
		start_2 = start_2 + strlen("loginName=");
		offset = (data + data_len) - start_2;
		if (offset < 1)
		{
			return HS_OK;
		}
		
		end_2 = DPI_StrnStr(start_2, "&login", offset);
		
		if (NULL == end_2)
		{
			return HS_OK;
		}

		va_type = VA_MAIL;
		start = start_2;
		account_len = end_2 - start_2;
	}else if (NULL != start_3)
	{	
		//查找到昵称标志
		start_3 = start_3 + strlen("_mu=");
		offset = (data + data_len) - start_3;
		if (offset < 1)
		{
			return HS_OK;
		}

		//为中文昵称
		//http报文中常见编码解码方式
		//%E4%B9%A6%E8%99%AB_LEAF 这里为先进行UTF-8编码为E4 B9 A6 E8 99 AB 在进行URL编码，每个
		//UTF-8编码前加一个%，需要注意的是UTF-8编码中汉字占3字节，Unicode中汉字占2字节
		//上述翻译为: 书虫_LEAF
		start_gb = DPI_StrnStr(start_3, "%7C", offset);
		if (NULL == start_gb)
		{
			return HS_OK;
		}
		offset = start_gb - start_3;
		start_3 = start_3 + offset + strlen("%7C");
		offset = (data + data_len) - start_3;
		if (offset < 1)
		{
			return HS_OK;
		}
		
		end_3 = DPI_StrnStr(start_3, "%7C", offset);
		if (NULL == end_3)
		{
			return HS_OK;
		}

		va_type = VA_NICKNAME;
		account_len = end_3 - start_3;
#if 0
		strncpy(input, start_3, account_len);

		//需要多次转码，后续研究
		gb18030_to_utf8(input, account_len , output, &output_len);
		account_len = strlen(output);
#endif
		
	}

    if (account_len >= ACCOUNT_MAX_LEN - 1) 
    {
        account_len = ACCOUNT_MAX_LEN - 1;
    }else if (account_len < 1)
	{
		return HS_OK;
	}

	HS_WRITE_LOCK_CTX(pstCtx);
	
    pstCtx->pstAccount = hs_malloc(sizeof(struct app_account));
    if (pstCtx->pstAccount != NULL)
    {
        memset(pstCtx->pstAccount, 0, sizeof(struct app_account));
        pstCtx->pstAccount->account_type = type;

		switch(va_type)
		{
			case VA_MAIL:
				ret = DPI_StrReplace(output, start, "%40", "@", account_len);
				if (HS_ERR == ret)
				{
					strncpy(pstCtx->pstAccount->account_buff, start, account_len);
				}else
				{	account_len = strlen(output);
					strncpy(pstCtx->pstAccount->account_buff, output, account_len);
					pstCtx->pstAccount->account_buff[account_len] = '\0';
				}
				break;
			case VA_NUM:
				strncpy(pstCtx->pstAccount->account_buff, start, account_len);
				break;
			case VA_NICKNAME:
				//strncpy(pstCtx->pstAccount->account_buff, output, account_len);
				strncpy(pstCtx->pstAccount->account_buff, start_3, account_len);
				break;
			default:
				return HS_OK;
		}
        HS_PLUGIN_IDENTIFY_STAT(HS_PLUGIN_ACCOUNT);
    }

    HS_WRITE_UNLOCK_CTX(pstCtx);
	
	return HS_OK;
}

static int MAOPU_Init(VOID)
{
	g_appid_maopu_login = GetAppId(DPI_MAOPU_LOGIN);
	g_appid_maopu_browser = GetAppId(DPI_MAOPU_BROWSER);
	if (IS_UNKNOWN_ID(g_appid_maopu_login) || IS_UNKNOWN_ID(g_appid_maopu_browser)) {
	    HS_INFO("account cann't find app(%s) or app(%s)\n", DPI_MAOPU_LOGIN, DPI_MAOPU_BROWSER);
		return HS_ERR;
	}

	return ACCOUNT_CreateHook(ACCOUNT_HOOK_MAOPU, MAOPU_Process, NULL, NULL);
}

static int TencentWeiBo_Process(HS_CTX_S *pstCtx, HS_PKT_DETAIL_S *pstDetail, void *priv)
{
	INT32 ret  = 0;
    INT32 account_len = 0;
	UINT32 va_type = 0;
	UINT32 offset = 0;
    UINT32 app_id;
    UINT32 data_len = 0;
	UINT32 len_start = 0;
    INT32  index = 0;
	UCHAR *data = NULL;
	UCHAR *start_1 = NULL;
	UCHAR *end_1 = NULL;
	
	DPI_ACCOUNT_E  type = ACCOUNT_MAX;

    if (pstCtx->pstAccount != NULL) 
	{
        return HS_OK;
    }

    app_id = atomic_read(&pstCtx->appid);
	data = pstDetail->data;
	data_len = pstDetail->length;

	if (app_id != g_appid_tencent_weibo_browser && app_id != g_appid_tencent_weibo_posts)
	{
		return HS_OK;
	}else 
	{
        HS_PLUGIN_DEAL_STAT(HS_PLUGIN_ACCOUNT);
			
		if (app_id == g_appid_tencent_weibo_browser)
		{
			type = ACCOUNT_TENCENT_WEIBO_BROWSER;
		}else if (app_id == g_appid_tencent_weibo_posts)
		{
			type = ACCOUNT_TENCENT_WEIBO_POSTS;
		}

		start_1 = DPI_StrnStr(data, "ptui_loginuin=", data_len);	//QQ、QQ邮箱
		if (NULL != start_1)
		{
			goto FOUND;
		}else 
		{
			return HS_OK;	
		}
	}
	
FOUND:
	if (NULL != start_1)
	{
		start_1 = start_1 + strlen("ptui_loginuin=");
		offset = (data + data_len) - start_1;
		if (offset < 1)
		{
			return HS_OK;
		}

		end_1 = DPI_StrnStr(start_1, ";", offset);
		if (NULL == end_1)
		{
			return HS_OK;
		}
		
		account_len = end_1 - start_1;
	}
		
    if (account_len >= ACCOUNT_MAX_LEN - 1) 
    {
        account_len = ACCOUNT_MAX_LEN - 1;
    }else if (account_len < 1)
	{
		return HS_OK;
	}

	HS_WRITE_LOCK_CTX(pstCtx);
    pstCtx->pstAccount = hs_malloc(sizeof(struct app_account));
    if (pstCtx->pstAccount != NULL)
    {
        memset(pstCtx->pstAccount, 0, sizeof(struct app_account));
        pstCtx->pstAccount->account_type = type;
		strncpy(pstCtx->pstAccount->account_buff, start_1, account_len);
	    HS_PLUGIN_IDENTIFY_STAT(HS_PLUGIN_ACCOUNT);
    }

	HS_WRITE_UNLOCK_CTX(pstCtx);
	
	return HS_OK;
}

static int TencentWeiBo_Init(VOID)
{
	g_appid_tencent_weibo_browser = GetAppId(DPI_TENCENT_WEIBO_BROWSER);
	g_appid_tencent_weibo_posts = GetAppId(DPI_TENCENT_WEIBO_POSTS);

	if (IS_UNKNOWN_ID(g_appid_tencent_weibo_browser) || IS_UNKNOWN_ID(g_appid_tencent_weibo_posts))
	{
	    HS_INFO("account cann't find app(%s) or app(%s)\n", DPI_TENCENT_WEIBO_BROWSER, DPI_TENCENT_WEIBO_POSTS);
		return HS_ERR;
	}

	return ACCOUNT_CreateHook(ACCOUNT_HOOK_TENCENT_WEI_BO, TencentWeiBo_Process, NULL, NULL);
}

static int RenRen_Process(HS_CTX_S *pstCtx, HS_PKT_DETAIL_S *pstDetail, void *priv)
{
	INT32 ret = 0;
    INT32 account_len = 0;
	UINT32 va_type = 0;
	UINT32 offset = 0;
    UINT32 app_id;
    UINT32 data_len = 0;
	UINT32 len_start = 0;
    INT32  index = 0;
	UCHAR *data = NULL;
	UCHAR *start = NULL;
	UCHAR *start_1 = NULL;
	UCHAR *end_1 = NULL;
	UCHAR *start_2 = NULL;
	UCHAR *end_2 = NULL;
	DPI_ACCOUNT_E type = ACCOUNT_MAX;

    if (pstCtx->pstAccount != NULL) 
	{
        return HS_OK;
    }

	app_id = atomic_read(&pstCtx->appid);
	data = pstDetail->data;
	data_len = pstDetail->length;

	if (app_id == g_appid_renren_login)
	{
        HS_PLUGIN_DEAL_STAT(HS_PLUGIN_ACCOUNT);
			
		type = ACCOUNT_RENREN_LOGIN;
		start_1 = DPI_StrnStr(data, "ln_uact=", data_len);	
        if (NULL != start_1)
		{
			goto FOUND;
		}
        
		start_2 = DPI_StrnStr(data, "email=", data_len);
		if (NULL != start_2)
		{
			goto FOUND;
		}
	} else 
	{
		return HS_OK;
	}
	
FOUND:
	if (NULL != start_1)
	{
		start_1 = start_1 + strlen("ln_uact=");
		offset = (data + data_len) - start_1;
		if (offset < 1)
		{
			return HS_OK;
		}

		end_1 = DPI_StrnStr(start_1, ";", offset);
		if (NULL == end_1)
		{
			return HS_OK;
		}

		start = start_1;
		account_len = end_1 - start_1;
		
	}

    if (NULL != start_2)
	{
		start_2 = start_2 + strlen("email=");
		offset = (data + data_len) - start_2;
		if (offset < 1)
		{
			return HS_OK;
		}

		end_2 = DPI_StrnStr(start_2, "&", offset);
		if (NULL == end_2)
		{
			return HS_OK;
		}

		start = start_2;
		account_len = end_2 - start_2;
	}
		
    if (account_len >= ACCOUNT_MAX_LEN - 1) 
    {
        account_len = ACCOUNT_MAX_LEN - 1;
    } else if (account_len < 1)
	{
		return HS_OK;
	}

	HS_WRITE_LOCK_CTX(pstCtx);
    pstCtx->pstAccount = hs_malloc(sizeof(struct app_account));
    if (pstCtx->pstAccount != NULL)
    {
        memset(pstCtx->pstAccount, 0, sizeof(struct app_account));
        pstCtx->pstAccount->account_type = type;
		strncpy(pstCtx->pstAccount->account_buff, start, account_len);
        HS_PLUGIN_IDENTIFY_STAT(HS_PLUGIN_ACCOUNT);
    }
    HS_WRITE_UNLOCK_CTX(pstCtx);
	
	return HS_OK;
}

static int RenRen_Init(VOID)
{
	g_appid_renren_login = GetAppId(DPI_RENREN_LOGIN);

	if (IS_UNKNOWN_ID(g_appid_renren_login))
	{
	    HS_INFO("account cann't find app(%s)\n", DPI_RENREN_LOGIN);
		return HS_ERR;
	}

	return ACCOUNT_CreateHook(ACCOUNT_HOOK_RENREN, RenRen_Process, NULL, NULL);
}

VOID  Account_AnalyzeProtocol(HS_CTX_S *pstCtx, HS_PKT_DETAIL_S *pstDetail, UINT32 uAppid)
{
    INT32     iRet = 0;
    UCHAR     ucBuf[2*ACCOUNT_MAX_LEN];
    UCHAR     ucAccount[2*ACCOUNT_MAX_LEN];
    UINT32    uIndex = 0;
    UINT32    uLen_Data = 0;
    UINT32    uLen_Tmp = 0;
    UINT32    uNodeNum = 0;
    UINT32    uProbeCount = 0;

    UCHAR    *pucAccStart = NULL;
    UCHAR    *pucAccEnd = NULL;
    UCHAR    *pucAccTmp = NULL;
    ACCOUNT_NODE_ASCII_S  *pstNode = NULL;

    uProbeCount = pstDetail->uProcCount;
    if (uProbeCount > ACCOUNT_SCAN_MAXNUM)
    {
        return;
    }

    if (NULL != pstCtx->pstAccount)
    {
        return;
    }
        
    if (UNKNOWN_ID == uAppid)
    {
        return;
    }

    if (NULL == pstDetail)
    {
        return;
    }

    uNodeNum = g_uNodeAccountNum;
    uLen_Data = pstDetail->length;
   
    for (uIndex = 0; uIndex < uNodeNum; uIndex++)
    {
        pstNode = &(g_stNodeAccount_Ascii[uIndex]);
        if ((uAppid != pstNode->appid) && ((uAppid != MASK_VERSION(pstNode->appid))))
        {
            continue;
        }

        HS_SET_DETECT_SUCCESS(pstCtx->flag);
        HS_PLUGIN_SET_MARKED(pstCtx,HS_HOOK_POST_DPI, HS_PLUGIN_ACCOUNT);

        pucAccStart = DPI_StrnStr(pstDetail->data, pstNode->sig_start, uLen_Data);
        if (NULL != pucAccStart)
        {
            pucAccTmp = pucAccStart + pstNode->sig_start_len;
            pucAccEnd = DPI_StrnChr(pucAccTmp, pstNode->sig_end, pstDetail->data+uLen_Data-pucAccTmp, pstNode->sig_end_seq);
            if (NULL != pucAccEnd) 
            {
                goto FOUND;
            }
        }
    }

    return;

FOUND:

    uLen_Tmp = pucAccEnd - pucAccTmp;
    if ((uLen_Tmp <= 0) || (uLen_Tmp >= (2*ACCOUNT_MAX_LEN)))
    {
        return;
    }
    
    memset(ucBuf, 0, 2*ACCOUNT_MAX_LEN);
    strncpy(ucBuf, pucAccTmp, uLen_Tmp);
    ucBuf[uLen_Tmp] = '\0';

    if (pstNode->str_find[0] != 0)
    {
        memset(ucAccount, 0, 2*ACCOUNT_MAX_LEN);
        iRet = DPI_StrReplace(ucAccount, ucBuf, pstNode->str_find, pstNode->str_replace, uLen_Tmp);
        if (HS_ERR == iRet)
        {
            return;
        }
    }
    else
    {
        strncpy(ucAccount, ucBuf, uLen_Tmp);
        ucAccount[uLen_Tmp] = '\0';
    }

    
    uLen_Tmp = strlen(ucAccount);
    if ((uLen_Tmp <= 0) || (uLen_Tmp >= ACCOUNT_MAX_LEN))
    {
        return;
    }

    HS_PLUGIN_SET_UNMARKED(pstCtx,HS_HOOK_POST_DPI, HS_PLUGIN_ACCOUNT);
    CHAR app[ACCOUNT_MAX_LEN];
    CHAR ip[16];
    HS_IpNtoa(1, pstDetail->tuple.addr.saddr, ip, 16);
    HS_FindAppNameByAppId(MASK_VERSION(pstCtx->appid), LANG_EN, app, ACCOUNT_MAX_LEN);
    HS_PRINT("[ACCOUNT]%s: %-40s account: %-50s\n", ip, app, ucAccount);
    HS_WARN("[ACCOUNT]%s: %-40s account: %-50s\n", ip, app, ucAccount);
    
    return;
}

int Account_Process(HS_CTX_S *pstCtx, HS_PKT_DETAIL_S *pstDetail, void **priv)
{
    ACCOUNT_HOOK_S *pstHook;
    
    if (pstDetail->length <= 0) {
		return HS_OK;
    }
	
    if (IS_UNKNOWN_ID(atomic_read(&pstCtx->appid))) {
		return HS_OK;
    }

    HS_read_lock(&g_stAccountRwlock);
    
    list_for_each_entry(pstHook, &g_stAccountHookHead, node) {
        pstHook->func(pstCtx, pstDetail, pstHook->priv);
    }
    
    HS_read_unlock(&g_stAccountRwlock);

    Account_AnalyzeProtocol(pstCtx, pstDetail, pstCtx->appid);

    if (pstCtx->pstAccount == NULL)
    {
        return HS_OK;
    }

    if ((pstCtx->pstAccount->flag == ACCOUNT_GET_FIRST) || (pstCtx->pstAccount->flag == ACCOUNT_GET_OTHER))
	{
	    CHAR app[ACCOUNT_MAX_LEN];
        CHAR ip[16];
        HS_IpNtoa(1, pstDetail->tuple.addr.saddr, ip, 16);
        HS_FindAppNameByAppId(MASK_VERSION(pstCtx->appid), LANG_EN, app, ACCOUNT_MAX_LEN);
        HS_PRINT("[ACCOUNT]%s: %-40s account: %-50s\n", ip, app, pstCtx->pstAccount->account_buff);
        HS_WARN("[ACCOUNT]%s: %-40s account: %-50s\n", ip, app, pstCtx->pstAccount->account_buff);
        pstCtx->pstAccount->flag = ACCOUNT_GET_MAX;
    }
	
    return HS_OK;
}

int HS_Account_Init(void)
{
    int err;
    HS_HOOK_OPS_S *ops = NULL;

    HS_rwlock_init(&g_stAccountRwlock);
    INIT_LIST_HEAD(&g_stAccountHookHead);
    
    ops = hs_malloc(sizeof(HS_HOOK_OPS_S));
	if (ops == NULL) {
		return HS_ERR;
	}

    INIT_LIST_HEAD(&ops->list);
	ops->hooknum = HS_HOOK_POST_DPI;
	ops->priority = HS_PLUGIN_ACCOUNT;
	ops->uDependPluginList = 0;
	ops->bEnable = TRUE;
	ops->fn = Account_Process;
	ops->destroy_fn = NULL;
	ops->pfnCtxPrivDestroy = NULL;
	ops->priv = NULL;
	
	err = HS_RegisterHook(ops);
	if (err != HS_OK) {
		goto ERROR;		
	}

    Account_InitGlobal();
	DPI_ACCOUNT_InitGlobal();
	
    /* account plugin begin */
    QQ_Init();
    WangWangChat_Init();
    SinaWeibo_Init();
    Fetion_Init();
	//BaiduLogin_Init();
	Wangyi126main_Init();
	Wangyi163main_Init();
    SMTP_Init();
    POP3_Init();
	//MAOPU_Init();
	TencentWeiBo_Init();
	RenRen_Init();
	DoubanLogin_Init();

    QQ_Mobile_Init();
    //Weixin_Mobile_Init();
	Weixin_Mobile_Init_2();
    /* account plugin end */

    return HS_OK;
ERROR:
    if (ops != NULL) {
        HS_UnregisterHook(ops->hooknum, ops->priority);	
		hs_free(ops);
    }

    return HS_ERR;
}
