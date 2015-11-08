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
#include "hs_mobile_info.h"

FILE *g_pstMobileInfoLog = NULL;
static HS_time_t mobile_info_ts;
UINT32 mobile_info_ts_delta = 60;

MOBILE_INFO_NODE_S g_stNodeMobileInfo[MOBILE_INFO_NODE_MAX] = {
	{"jing-dong-mobile_1",  			"uuid=",    		'-', 	IMEI_FLAG, 	BREAK_PARSER,		0},
	{"tao-bao-mobile_1",  				"imei=",    		'&', 	IMEI_FLAG, 	CONTINUE_PARSER,	0},
	{"tao-bao-mobile_1",  				"imsi=",    		'&', 	IMSI_FLAG, 	BREAK_PARSER,		0},
	{"tao-bao-mobile_3",  				"deviceid=",    	'&', 	IMEI_FLAG, 	BREAK_PARSER,		0},
	{"mei-tuan-mobile_1",  				"utm_content=",    	'&', 	IMEI_FLAG, 	BREAK_PARSER,		0},
	{"you-ku-mobile_1",  				"imei=",    		'&', 	IMEI_FLAG, 	CONTINUE_PARSER,	0},
	{"you-ku-mobile_1",  				"imsi=",    		'&', 	IMSI_FLAG, 	CONTINUE_PARSER,	0},
	{"you-ku-mobile_1",  				"mob=%2B",    		'&', 	PHONE_FLAG, BREAK_PARSER,		0},
	{"ai-qi-yi-mobile_1",				"qyid=",    		'&', 	IMEI_FLAG, 	BREAK_PARSER,		0},
	{"ku-gou-mobile_1",					"simno=",    		'&', 	IMSI_FLAG, 	CONTINUE_PARSER,	0},
	{"ku-gou-mobile_1",					"imei=",    		'&', 	IMEI_FLAG, 	BREAK_PARSER,		0},
	{"PPTV-mobile_1",  					"did=",    			'&', 	IMEI_FLAG, 	CONTINUE_PARSER,	0},
	{"PPTV-mobile_1",  					"carrier=",    		'&', 	IMSI_FLAG, 	BREAK_PARSER,		0},
	{"ku-wo-yin-yue-mobile_1",			"cid=",    			'&', 	IMEI_FLAG, 	BREAK_PARSER,		0},
	{"ku-wo-yin-yue-mobile_2",  		"user=",    		'&', 	IMEI_FLAG, 	CONTINUE_PARSER,	0},
	{"ku-wo-yin-yue-mobile_2",  		"imsi=",    		'&', 	IMSI_FLAG, 	BREAK_PARSER,		0},
	{"duo-mi-yin-yue-mobile_1",  		"imei=",    		'&', 	IMEI_FLAG, 	CONTINUE_PARSER,	0},
	{"duo-mi-yin-yue-mobile_1",  		"imsi=",    		'&', 	IMSI_FLAG, 	CONTINUE_PARSER,	0},
	{"duo-mi-yin-yue-mobile_1",  		"cn=",    			'&', 	PHONE_FLAG, BREAK_PARSER,		0},
	{"qq-news-mobile_1",				"devid=",			'&', 	IMEI_FLAG, 	CONTINUE_PARSER,	0},
	{"qq-news-mobile_1",				"imsi=",			'&', 	IMSI_FLAG, 	BREAK_PARSER,		0},
	{"tou-tiao-mobile_1",				"uuid=",    		'&', 	IMEI_FLAG, 	BREAK_PARSER,		0},
	{"bai-du-yin-yue-mobile_1",			"deviceid: ",    	'\r', 	IMEI_FLAG, 	BREAK_PARSER,		0},
	{"ali-yun-mobile_1",  				"imei=",    		'&', 	IMEI_FLAG, 	CONTINUE_PARSER,	0},
	{"ali-yun-mobile_1",  				"mob=%2B",    		'&', 	PHONE_FLAG, BREAK_PARSER,		0},
	{"tian-tian-dong-ting-mobile_1",	"uid=",				'&', 	IMEI_FLAG, 	CONTINUE_PARSER,	0},
	{"tian-tian-dong-ting-mobile_1",	"imsi=",			'&', 	IMSI_FLAG, 	BREAK_PARSER,		0},
	{"tian-tian-dong-ting-mobile_2",  	"imsi=",    		'&', 	IMSI_FLAG, 	CONTINUE_PARSER,	0},
	{"tian-tian-dong-ting-mobile_2",  	"phone=",    		'&', 	PHONE_FLAG, BREAK_PARSER,		0},	
	{"bai-du-di-tu-mobile_1",			"im=",    			'&', 	IMEI_FLAG, 	CONTINUE_PARSER,	0},
	{"bai-du-di-tu-mobile_1",			"imei=",    		'&', 	IMEI_FLAG, 	BREAK_PARSER,		0},
	{"bai-du-di-tu-mobile_2",			"openudid=",    	'&', 	IMEI_FLAG, 	BREAK_PARSER,		0},
	{"bai-du-di-tu-mobile_3",			"imei=",	    	'&', 	IMEI_FLAG, 	BREAK_PARSER,		0},
	{"bao-feng-ying-yin-mobile_1",		"imei=",    		'&', 	IMEI_FLAG, 	BREAK_PARSER,		0},
	{"bao-feng-ying-yin-mobile_2",		"uid=",    			'&', 	IMEI_FLAG, 	BREAK_PARSER,		0},
	{"da-zhong-dian-pin-mobile_1",		"deviceid=",  		'&',	IMEI_FLAG, 	BREAK_PARSER,		0},
	{"da-zhong-dian-pin-mobile_2",		"imei=",    		'&',	IMEI_FLAG, 	BREAK_PARSER,		0},
	{"da-zhong-dian-pin-mobile_3",		"pragma-device: ",  '\r',	IMEI_FLAG, 	BREAK_PARSER,		0},
	{"da-zhong-dian-pin-mobile_4",		"device\":\"",  	'\"',	IMEI_FLAG, 	BREAK_PARSER,		0},
	{"wifi-wan-neng-yao-shi_1",			"ii=",    			'&',	IMEI_FLAG, 	BREAK_PARSER,		0},
	{"wifi-wan-neng-yao-shi_2",			"imei=",    		'&',	IMEI_FLAG, 	BREAK_PARSER,		0},
	{"dang-dang-mobile_1",				"imei=",    		'&',	IMEI_FLAG, 	BREAK_PARSER,		0},
	{"mo-ji-tian-qi-mobile_2",			"IMEI=",    		' ',	IMEI_FLAG, 	CONTINUE_PARSER,	0},
	{"mo-ji-tian-qi-mobile_2",			"IMEI=",    		'&',	IMEI_FLAG, 	BREAK_PARSER,		0},
	{"hao-dou-cai-pu-mobile_1",			"deviceid=haodou",  '&',	IMEI_FLAG, 	BREAK_PARSER,		0},
	{"le-an-quan_2",					"deviceid=",  		' ',	IMEI_FLAG, 	CONTINUE_PARSER,	0},
	{"le-an-quan_2",					"did=",  			'&',	IMEI_FLAG, 	BREAK_PARSER,		0},
	{"ren-ren-mobile_1",				"imei%22%3A%22",  	'%',	IMEI_FLAG, 	BREAK_PARSER,		0},
    {"zhi-fu-bao-mobile_1",				"userId=",  	    '&',	IMEI_FLAG, 	BREAK_PARSER,		0}, 

    {"di-di-chu-xing_1",                "imei=",    		'&',	IMEI_FLAG, 	BREAK_PARSER,		0},

    /*注意此处往下是需要挎包提取特征的*/
	{"mo-ji-tian-qi-mobile_1",			"identifier\":\"",  '\"',	IMEI_FLAG, 	BREAK_PARSER,		1},
	{"le-an-quan_1",					"imei\x01",  		'\x01',	IMEI_FLAG, 	BREAK_PARSER,		1},
    /*注意不要越界，END 为结束标志*/
	{"END", "", ' '},
};

HS_rwlock_t g_stMobileInfoNodeRwlock;

UINT32 g_uNodeMobileInfoNum = 0;
UINT32 g_uNodeMobileInfoMarkStart = 0;


extern UCHAR *DPI_StrnStr(UCHAR *pucSrc, UCHAR *pucSub, UINT32 uSrcLen);
extern UCHAR *DPI_StrnChr(UCHAR *pucSrc, UCHAR ucSub, UINT32 uSrcLen, UINT32  uSeq);


VOID Mobile_Info_GlobalNode_Init()
{
    UINT32    uIndex = 0;
    UINT32    uAppid = 0;
	UINT32	  uFlag = 0;
    MOBILE_INFO_NODE_S  *pstNode = NULL;

    for (uIndex = 0; uIndex < MOBILE_INFO_NODE_MAX; uIndex++)
    {
        pstNode = &(g_stNodeMobileInfo[uIndex]);
        if (0 == strncmp(pstNode->name, "END", 3))
        {
            break;
        }

		if (uFlag == 0 && pstNode->mark_flag == 1)
		{
			uFlag = 1;
			g_uNodeMobileInfoMarkStart = g_uNodeMobileInfoNum;
			
		}

        uAppid = HS_FindAppIdByAppName(pstNode->name, LANG_EN);
        pstNode->appid = uAppid;
        g_uNodeMobileInfoNum++;
    }

}

static INT32 OutputMobileInfo(const CHAR *pcLogMod, HS_time_t tv, CHAR *pcBuff)
{
    CHAR log_name[64];

START:
    if (g_pstMobileInfoLog == NULL) {
        AssignLogName(pcLogMod, tv, log_name, sizeof(log_name));
        g_pstMobileInfoLog = fopen(log_name, "w+");
        if (g_pstMobileInfoLog == NULL) {
            return HS_ERR;
        }

        mobile_info_ts = tv;
    }

    if (tv.tv_sec > mobile_info_ts.tv_sec + mobile_info_ts_delta) {
        fclose(g_pstMobileInfoLog);
        g_pstMobileInfoLog = NULL;
        goto START;
    }

    fwrite(pcBuff, 1, strlen(pcBuff), g_pstMobileInfoLog);
    fwrite("\r\n", 1, 2, g_pstMobileInfoLog);

    return HS_OK;
}

void LogMobileInfo(HS_PKT_DETAIL_S *pstDetail, CHAR *pcApp, CHAR *pcType, CHAR *pcVaule)
{
    char buff[1024];
    UINT32 uLen = 0;

    if (pcApp == NULL || pcVaule == NULL) {
        return;
    }

    if (strlen(pcApp) == 0 || strlen(pcVaule) == 0) {
        return;
    }

    uLen += HS_MakeTime(pstDetail->ts, buff, sizeof(buff));
    buff[uLen++] = '\t';

    uLen += HS_MakeTuple6(pstDetail, buff + uLen, sizeof(buff) - uLen);
    buff[uLen++] = '\t';

    memcpy(buff + uLen, pcApp, strlen(pcApp));
    uLen += strlen(pcApp);
    buff[uLen++] = '\t';

    if (pcType == NULL || strlen(pcType) == 0) {
        memcpy(buff + uLen, "unknown", strlen("unknown"));
        uLen += strlen("unknown");
        buff[uLen++] = '\t';
    }
    
    memcpy(buff + uLen, pcVaule, strlen(pcVaule));
    uLen += strlen(pcVaule);
    buff[uLen++] = '\t';
    
    buff[uLen++] = '\0';

    HS_PRINT(buff);
    HS_WARN(buff);
    OutputMobileInfo("gw_ImeiImsi", pstDetail->ts, buff);
}

int Mobile_Info_Process(HS_CTX_S *pstCtx, HS_PKT_DETAIL_S *pstDetail, void **priv)
{
	UINT32    uNodeNum = 0;
	UINT32    uLen_Data = 0;
	UINT32    uIndex = 0;
	MOBILE_INFO_NODE_S  *pstNode = NULL;

	UCHAR    *pucSigStart = NULL;
	UCHAR    *pucSigStartTmp = NULL;
	UCHAR    *pucSigEndTmp = NULL;
	UINT32    uLen_Tmp = 0;
	UCHAR     ucBuf[IMEI_INFO_MAX];
	
    
    if (pstDetail->length <= 0) {
		return HS_OK;
    }
	
    if (IS_UNKNOWN_ID(atomic_read(&pstCtx->appid))) {
		return HS_OK;
    }

	uNodeNum = g_uNodeMobileInfoNum;
    uLen_Data = pstDetail->length;

	if (HS_PLUGIN_UNMARKED(pstCtx, HS_HOOK_POST_DPI, HS_PLUGIN_MOBILEINFO))
	{
		uIndex = 0;
	}
	else
	{
		uIndex = g_uNodeMobileInfoMarkStart;
	}

#if 0
	pstCtx->pstMobileInfo = NULL;
#endif

	for (; uIndex < uNodeNum; uIndex++)
    {
    	pucSigStart = NULL;
    	pucSigStartTmp = NULL;
    	pucSigEndTmp = NULL;
    	uLen_Tmp = 0;
		
        pstNode = &(g_stNodeMobileInfo[uIndex]);

		if (HS_PLUGIN_UNMARKED(pstCtx, HS_HOOK_POST_DPI, HS_PLUGIN_MOBILEINFO))
		{
	        if (pstCtx->appid != pstNode->appid)
	        {
	            continue;
	        }

			if (pstNode->mark_flag == 1)
			{
				HS_PLUGIN_SET_MARKED(pstCtx, HS_HOOK_POST_DPI, HS_PLUGIN_MOBILEINFO);
				return HS_OK;
			}
		}
		else
		{
			if (pstCtx->appid != MASK_VERSION(pstNode->appid))
	        {
	            continue;
	        }
		}

        //HS_SET_MARKED(pstCtx->flag);
        pucSigStart = DPI_StrnStr(pstDetail->data, pstNode->sig_start, uLen_Data);
        if (NULL != pucSigStart)
        {
            pucSigStartTmp = pucSigStart + strlen(pstNode->sig_start);
            pucSigEndTmp = DPI_StrnChr(pucSigStartTmp, pstNode->sig_end, uLen_Data - (pucSigStartTmp - pstDetail->data), 1);
            if (NULL != pucSigEndTmp) 
            {
				uLen_Tmp = pucSigEndTmp - pucSigStartTmp;
				if ((uLen_Tmp < 0) || (pstNode->type_info == IMEI_FLAG && uLen_Tmp >= (IMEI_INFO_MAX))
					|| (pstNode->type_info == IMSI_FLAG && uLen_Tmp >= (IMSI_INFO_MAX))
					|| (pstNode->type_info == PHONE_FLAG && uLen_Tmp >= (PHONE_INFO_MAX)))
			    {
			        return HS_ERR;
			    }

				if (pstCtx->pstMobileInfo == NULL)
				{
					pstCtx->pstMobileInfo = hs_malloc(sizeof(MOBILE_INFO_S));
					if (pstCtx->pstMobileInfo == NULL)
					{
						return HS_ERR;
					}
					memset(pstCtx->pstMobileInfo, 0, sizeof(MOBILE_INFO_S));
				}

				if (pstNode->type_info == IMEI_FLAG)
				{
			    	strncpy(pstCtx->pstMobileInfo->IMEI_buff, pucSigStartTmp, uLen_Tmp);
					pstCtx->pstMobileInfo->IMEI_buff[uLen_Tmp] = '\0';
				}
				else if (pstNode->type_info == IMSI_FLAG)
				{
					strncpy(pstCtx->pstMobileInfo->IMSI_buff, pucSigStartTmp, uLen_Tmp);
					pstCtx->pstMobileInfo->IMSI_buff[uLen_Tmp] = '\0';
				}
				else if (pstNode->type_info == PHONE_FLAG)
				{
					strncpy(pstCtx->pstMobileInfo->PHONE_buff, pucSigStartTmp, uLen_Tmp);
					pstCtx->pstMobileInfo->PHONE_buff[uLen_Tmp] = '\0';
				}

				//HS_SET_UNMARKED(pstCtx->flag);

				HS_SET_MOBILE_INFO_MARKED(pstCtx->pstMobileInfo->info_type_flag, pstNode->type_info);


				if (pstNode->parser_action == CONTINUE_PARSER)
				{
					continue;
				}
				else if(pstNode->parser_action == BREAK_PARSER)
				{
					break;
				}

            }
        }
    }

	if(pstNode->mark_flag == 1)
	{
		HS_PLUGIN_SET_UNMARKED(pstCtx, HS_HOOK_POST_DPI, HS_PLUGIN_MOBILEINFO);
	}

#if 1

	if (pstCtx->pstMobileInfo == NULL)
	{
		return HS_ERR;
	}

	CHAR app[MOBLIE_APP_NAME_MAXLEN];
    HS_FindAppNameByAppId(MASK_VERSION(pstCtx->appid), LANG_EN, app, MOBLIE_APP_NAME_MAXLEN);

	if (HS_TEST_MOBILE_INFO_MARKED(pstCtx->pstMobileInfo->info_type_flag, IMEI_FLAG))
	{	    
		HS_PRINT("[IMSI/IMEI]Mobile IMEI Info: %-40s %-50s\n", app, pstCtx->pstMobileInfo->IMEI_buff);
		HS_WARN("[IMSI/IMEI]Mobile IMEI Info: %-40s %-50s\n", app, pstCtx->pstMobileInfo->IMEI_buff);
        LogMobileInfo(pstDetail, app, "IMEI", pstCtx->pstMobileInfo->IMEI_buff);
	}
	
	if (HS_TEST_MOBILE_INFO_MARKED(pstCtx->pstMobileInfo->info_type_flag, IMSI_FLAG))
	{
		HS_PRINT("[IMSI/IMEI]Mobile IMSI Info: %-40s %-50s\n", app, pstCtx->pstMobileInfo->IMSI_buff);
    	HS_WARN("[IMSI/IMEI]Mobile IMSI Info: %-40s %-50s\n", app, pstCtx->pstMobileInfo->IMSI_buff);
        LogMobileInfo(pstDetail, app, "IMSI", pstCtx->pstMobileInfo->IMEI_buff);
	}
	
	if (HS_TEST_MOBILE_INFO_MARKED(pstCtx->pstMobileInfo->info_type_flag, PHONE_FLAG))
	{
		HS_PRINT("[IMSI/IMEI]Mobile PHONE Info: %-40s %-50s\n", app, pstCtx->pstMobileInfo->PHONE_buff);
    	HS_WARN("[IMSI/IMEI]Mobile PHONE Info: %-40s %-50s\n", app, pstCtx->pstMobileInfo->PHONE_buff);
        LogMobileInfo(pstDetail, app, "PHONE-NO", pstCtx->pstMobileInfo->PHONE_buff);
	}

	hs_free(pstCtx->pstMobileInfo);
	pstCtx->pstMobileInfo = NULL;
#endif

    return HS_OK;
	
}


int HS_Mobile_Info_Init(void)
{
    int err;
    HS_HOOK_OPS_S *ops = NULL;

    HS_rwlock_init(&g_stMobileInfoNodeRwlock);
    
    ops = hs_malloc(sizeof(HS_HOOK_OPS_S));
	if (ops == NULL) {
		return HS_ERR;
	}

    INIT_LIST_HEAD(&ops->list);
	ops->hooknum = HS_HOOK_POST_DPI;
	ops->priority = HS_PLUGIN_MOBILEINFO;
	ops->uDependPluginList = 0;
	ops->bEnable = TRUE;
	ops->fn = Mobile_Info_Process;
	ops->destroy_fn = NULL;
	ops->pfnCtxPrivDestroy = NULL;
	ops->priv = NULL;
	
	err = HS_RegisterHook(ops);
	if (err != HS_OK) {
		goto ERROR;		
	}

    Mobile_Info_GlobalNode_Init();

    return HS_OK;
ERROR:
    if (ops != NULL) {
        HS_UnregisterHook(ops->hooknum, ops->priority);	
		hs_free(ops);
    }

    return HS_ERR;
}

