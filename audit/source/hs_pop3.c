#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "hs.h"
#include "hs_consts.h"
#include "hs_core.h"
#include "hs_stat.h"
#include "hs_smtp.h"

extern INT32 HS_Mime_Process(char *data, int len, MAIL_DATA_INFO *psmtpInfo, FILE *fp);


INT32 HS_Pop3_Process(HS_CTX_S *ctx, HS_PKT_DETAIL_S *detail, void **priv)
{
    char *pIndex = NULL;
    char *pdata_start = NULL;
    char *pPop3_data = NULL;
    INT32 limit = 0;
    int ret;
    MAIL_DATA_INFO *pstMail_info = ctx->pstMail_info;
    time_t rawtime;
    FILE *fp;
    
    if (detail->tuple.addr.dest != 110)
    {
        return HOOK_ACTION_CONTINUE;
    }

    if( HS_PLUGIN_UNMARKED(ctx, HS_HOOK_POST_DPI, HS_PLUGIN_POP3)) 
    {
#if 0
        time( &rawtime );
        sprintf(smtp_data->mail_log_name, "%d%d-%d.log", detail->tuple.addr.saddr, detail->tuple.addr.source, rawtime);
        printf("%s\r\n", smtp_data->mail_log_name);
#endif	
		//ctx->pstMail_info = pstMail_info = NULL;
        HS_PLUGIN_SET_MARKED(ctx, HS_HOOK_POST_DPI, HS_PLUGIN_POP3);     
    } 
	
	pPop3_data = detail->data;


    if (pstMail_info != NULL && pstMail_info->mail_flag != MIME_NONE)
    {
	    fp = fopen(pstMail_info->mail_log_name, "a+");
	    if (fp == NULL)
	    {
	            return HOOK_ACTION_CONTINUE;
	    }
	    fseek(fp, 0L, 2);
		
        limit = detail->length;;

        ret = HS_Mime_Process(pPop3_data, limit, pstMail_info, fp);
        if (ret == MIME_END)
        {
            HS_PLUGIN_SET_UNMARKED(ctx, HS_HOOK_POST_DPI, HS_PLUGIN_POP3);
    
            HS_SET_DETECT_SUCCESS(ctx->flag);
        }

		fclose(fp);
		goto PROCESS_END;
    }

    if((detail->length > strlen(POP3_RETR_START)) && (!strncmp(pPop3_data, POP3_RETR_START, strlen(POP3_RETR_START))))
    {
		if (pstMail_info == NULL)
	    {

	        pstMail_info = (MAIL_DATA_INFO *) hs_malloc(sizeof(MAIL_DATA_INFO));
	        if(pstMail_info == NULL)
	        {
	            return HOOK_ACTION_CONTINUE;
	        }
	        memset(pstMail_info, 0, sizeof(MAIL_DATA_INFO));

	        ctx->pstMail_info = pstMail_info;
	        
	        time( &rawtime );			
	        sprintf(pstMail_info->mail_log_name, "%d%d-%d.log", detail->tuple.addr.saddr, detail->tuple.addr.source, rawtime);	   
			printf("%s\r\n", pstMail_info->mail_log_name);
	    }

		pstMail_info ->mail_flag = MIME_HEAD;
    }    

PROCESS_END:
    
    return HOOK_ACTION_CONTINUE;
}

INT32 HS_Pop3_Init(void)
{
    INT32 ret;
    HS_HOOK_OPS_S *ops = NULL;
    
    ops = hs_malloc(sizeof(HS_HOOK_OPS_S));
    if(ops == NULL) 
    {
        return HS_ERR;
    }

    INIT_LIST_HEAD(&ops->list);
    ops->hooknum = HS_HOOK_POST_DPI;
    ops->priority = HS_PLUGIN_POP3;
    ops->uDependPluginList = 0;
    ops->bEnable = TRUE;
    ops->fn = HS_Pop3_Process;
    ops->destroy_fn = NULL;
    ops->pfnCtxPrivDestroy= NULL;
    ops->priv = NULL;

    ret = HS_RegisterHook(ops);
    if(ret != HS_OK)
    {
        goto ERROR;		
    }

    return HS_OK;

    ERROR:
    if(ops)
    {
        HS_UnregisterHook(ops->hooknum, ops->priority);
        hs_free(ops);
    }

    return HS_ERR;
}

