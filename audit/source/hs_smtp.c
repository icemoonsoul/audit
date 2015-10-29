#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "hs.h"
#include "hs_consts.h"
#include "hs_core.h"
#include "hs_stat.h"
#include "hs_smtp.h"

const char * base64char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

extern UCHAR *DPI_StrnStr(UCHAR *pucSrc, UCHAR *pucSub, UINT32 uSrcLen);
extern UCHAR *DPI_StrnChr(UCHAR *pucSrc, UCHAR ucSub, UINT32 uSrcLen, UINT32  uSeq);

int base64_decode( const char * base64, unsigned char * bindata )
{
    int i, j;
    unsigned char k;
    unsigned char temp[4];
    for ( i = 0, j = 0; base64[i] != '\0' ; i += 4 )
    {
        memset( temp, 0xFF, sizeof(temp) );
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i] )
                temp[0]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+1] )
                temp[1]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+2] )
                temp[2]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+3] )
                temp[3]= k;
        }

        bindata[j++] = ((unsigned char)(((unsigned char)(temp[0] << 2))&0xFC)) |
                ((unsigned char)((unsigned char)(temp[1]>>4)&0x03));
        if ( base64[i+2] == '=' )
            break;

        bindata[j++] = ((unsigned char)(((unsigned char)(temp[1] << 4))&0xF0)) |
                ((unsigned char)((unsigned char)(temp[2]>>2)&0x0F));
        if ( base64[i+3] == '=' )
            break;

        bindata[j++] = ((unsigned char)(((unsigned char)(temp[2] << 6))&0xF0)) |
                ((unsigned char)(temp[3]&0x3F));
    }
    return j;
}

char * smtp_data_move(char *data, char *limit, char *src)
{
    char *pIndex = NULL;
	int len = limit - data;
    
    pIndex = DPI_StrnStr(data, src, len);
    if (pIndex == NULL)
    {
        return NULL;
    }

    pIndex = pIndex + strlen(src);
    if (pIndex > limit)
    {
        return NULL;
    }

    return pIndex;
}

INT32 mime_process_to(char *data, int len, FILE *fp)
{
    char *pStart = data;
    char *pdata_end = data + len;
    char *pEnd = NULL;
    char *pIndex = NULL;

    int state = 0;

    char ptmp[SMTP_BUFF_LEN] = {0};
    unsigned  char pdecode[SMTP_BUFF_LEN] = {0};
    int base64 = 0;

    while(pStart < pdata_end)
    {
        pIndex = smtp_data_move(pStart, pdata_end, GB2312_KEY);
        if (pIndex != NULL)
        {
            pEnd = smtp_data_move(pStart, pdata_end, GB2312_END);
            if (pEnd == NULL)
            {
                return 1;
            }

            state = pEnd - pStart;

			if(state >= SMTP_BUFF_LEN)
			{
				return 1;
			}
			
            strncpy(ptmp, pStart, state);
            ptmp[state] = '\0';

            base64_decode(ptmp, pdecode);
            state = (state * 3) / 4;
            pdecode[state] = '\0';
            fprintf(fp, "to:%s", pdecode);
            pStart = pEnd;
        }
        else
        {
            fprintf(fp, "to:");
        }

        pEnd = smtp_data_move(pStart, pdata_end, ">,");
        if (pEnd == NULL)
        {
            pEnd = data + len;
        }

        state = pEnd - pStart;
		if(state >= SMTP_BUFF_LEN)
		{
			return 1;
		}
        strncpy(ptmp, pStart, state);
        ptmp[state] = '\0';
        fprintf(fp, "%s", ptmp);

        pStart = pEnd;  
    }

    return 0;
}

INT32 dpi_mime_process(char *data, int len, SMTP_DATA_INFO *psmtpInfo, FILE *fp)
{
    char *pdata_end = NULL;
    char *pIndex = NULL;
    char *pStart = NULL;
    char *pEnd = NULL;
    int ret;
    int state = 0;
	int limit = 0;

    char ptmp[128] = {0};
    unsigned  char pdecode[128] = {0};
    int base64 = 0;

    pStart = data;
    pdata_end = data + len;

    if (data == NULL || psmtpInfo == NULL || fp == NULL)
    {
        return SMTP_END;
    }

    pIndex = DPI_StrnStr(data, SMTP_DATA_END, len);
    if(pIndex == NULL || pIndex > pdata_end)
    {
        ret = SMTP_END;
    }

    if (psmtpInfo->smtp_flag == SMTP_DATA)
    {
        pStart = smtp_data_move(pStart, pdata_end, MIME_FROM);
        if (pStart == NULL)
        {
            return 1;
        }

        psmtpInfo->smtp_flag = MIME_FROM_START;
    }

    if (psmtpInfo->smtp_flag == MIME_FROM_START)
    {
        pIndex = smtp_data_move(pStart, pdata_end, GB2312_KEY);
        if (pIndex != NULL)
        {
            pEnd = smtp_data_move(pStart, pdata_end, GB2312_END);
            if (pEnd == NULL)
            {
                return 1;
            }

            state = pEnd - pStart;
			if(state >= SMTP_BUFF_LEN)
			{
				return 1;
			}
            strncpy(ptmp, pStart, state);
            ptmp[state] = '\0';

            base64_decode(ptmp, pdecode);
            state = (state * 3) / 4;
            pdecode[state] = '\0';
            fprintf(fp, "from:%s", pdecode);
            pStart = pEnd;
        }
        else
        {
            fprintf(fp, "from:");
        }

        pEnd = smtp_data_move(pStart, pdata_end, "\r\n");
        if (pEnd == NULL)
        {
            return 1;
        }

        state = pEnd - pStart;
		if(state >= SMTP_BUFF_LEN)
		{
			return 1;
		}
        strncpy(ptmp, pStart, state);
        ptmp[state] = '\0';
        fprintf(fp, "%s", ptmp);

        pStart = pEnd;
        psmtpInfo->smtp_flag = MIME_FROM_END;
    }

    if (psmtpInfo->smtp_flag == MIME_FROM_END)
    {
        pStart = smtp_data_move(pStart, pdata_end, MIME_TO);
        if (pStart == NULL)
        {
            return 1;
        }

        psmtpInfo->smtp_flag = MIME_TO_START;
    }

    if (psmtpInfo->smtp_flag == MIME_TO_START)
    {
        pEnd = smtp_data_move(pStart, pdata_end, "\r\n");
        if (pEnd == NULL)
        {
            return 1;
        }

        state = pEnd - pStart;
        if (mime_process_to(pStart, state, fp))
        {
            return 1;
        }

        pStart = pEnd;
        psmtpInfo->smtp_flag = MIME_TO_END;
    }
    
    if (psmtpInfo->smtp_flag == MIME_TO_END)
    {
#if 0
        pIndex = strstr(pStart, MIME_SUBJECT);
        if (pIndex == NULL)
        {
            return 1;
        }

        pStart = pIndex + strlen(MIME_SUBJECT);

        if (pStart > pdata_end)
        {
            return 1;
        }
#endif
        pStart = smtp_data_move(pStart, pdata_end, MIME_SUBJECT);
        if (pStart == NULL)
        {
            return 1;
        }
        
        psmtpInfo->smtp_flag = MIME_SUBJCT_START;
    }

    if (psmtpInfo->smtp_flag ==MIME_SUBJCT_START)
    {
        if (pStart[0] == '=')       /* base64½âÂë */
        {
            pStart = pStart + strlen(GB2312_KEY);
            if (pStart > pdata_end)
            {
                return 1;
            }
            base64 = 1;
        }  

		limit = pdata_end - pStart;
        pIndex = DPI_StrnStr(pStart, "\r\n", limit);
        if (pIndex == NULL || pIndex > pdata_end)
        {
            return 1;
        }

        pEnd = pIndex;

        if (base64 == 1)
        {
            state = pEnd - pStart;
			if(state >= SMTP_BUFF_LEN)
			{
				return 1;
			}
            strncpy(ptmp, pStart, state);
            ptmp[state] = '\0';
            
            base64_decode(ptmp, pdecode);
            state = (state * 3) / 4;
            pdecode[state] = 0;
            fprintf(fp, "%s\r\n", pdecode);
            base64 = 0;
        }
        else
        {
            state = pEnd - pStart;
			if(state >= SMTP_BUFF_LEN)
			{
				return 1;
			}
            strncpy(ptmp, pStart, state);
            ptmp[state] = '\0';
            printf("%s\r\n", ptmp);
            fprintf(fp, "%s\r\n", ptmp);
        }
        psmtpInfo->smtp_flag = MIME_SUBJCT_END;

        pStart = pIndex + strlen("\r\n");

        if (pStart > pdata_end)
        {
            return 1;
        }
    }

    if (psmtpInfo->smtp_flag == MIME_SUBJCT_END)
    {
#if 0
        pIndex = strstr(pStart, MIME_CONTENT);

        if(pIndex == NULL)
        {
            return 1;
        }

        pStart = pIndex + strlen(MIME_CONTENT);

        if(pStart > pdata_end)
        {
            return 0;
        }
#endif

        pStart = smtp_data_move(pStart, pdata_end, MIME_CONTENT);
        if (pStart == NULL)
        {
            return 1;
        }
        
        psmtpInfo->smtp_flag = MIME_CONTENT_START;
    }

    if (psmtpInfo->smtp_flag == MIME_CONTENT_START)
    {
#if 0
        pIndex = strstr(pStart, MIME_TEXT_ENCODE);

        if (pIndex == NULL)
        {
            return 1;
        }

        pStart = pIndex + strlen(MIME_TEXT_ENCODE);

        if(pStart > pdata_end)
        {
            return 1;
        }
#endif
        pStart = smtp_data_move(pStart, pdata_end, MIME_TEXT_ENCODE);
        if (pStart == NULL)
        {
            return 1;
        }

        if(!strncmp(pStart, BASE64_KEY, strlen(BASE64_KEY)))
        {
            base64 = 1;
        }

        psmtpInfo->smtp_flag = MIME_ENCODE_START;
    }

    if (psmtpInfo->smtp_flag == MIME_ENCODE_START)
    {
#if 0
        pIndex = strstr(pStart, "\r\n\r\n");

        if (pIndex == NULL)
        {
            return 1;
        }

        pStart = pIndex + strlen("\r\n\r\n");

        if (pStart > pdata_end)
        {
            return 1;
        }
#endif
        pStart = smtp_data_move(pStart, pdata_end, "\r\n\r\n");
        if (pStart == NULL)
        {
            return 1;
        }

        psmtpInfo->smtp_flag = MIME_ENCODE_END;
    }

    if (psmtpInfo->smtp_flag == MIME_ENCODE_END)
    {
    	limit = pdata_end - pStart;
        pIndex = DPI_StrnStr(pStart, "\r\n\r\n", limit);

        if (pIndex == NULL)
        {
            return 1;
        }

        pEnd= pIndex + strlen("\r\n\r\n");

        if (pEnd > pdata_end)
        {
            return 1;
        }

        state = pEnd - pStart;
		if(state >= SMTP_BUFF_LEN)
		{
			return 1;
		}
        strncpy(ptmp, pStart, state);
        ptmp[state] = '\0';

        if (base64 == 1)
        {
            base64_decode(ptmp, pdecode);
            printf("%s\r\n", pdecode);
            fprintf(fp, "%s\r\n", pdecode);
        }
        else
        {
            printf("%s\r\n", ptmp);
            fprintf(fp, "%s\r\n", ptmp);
        }
        psmtpInfo->smtp_flag = MIME_CONTENT_END;
    }

    return 0;
    
}

INT32 dpi_smtp_process(HS_CTX_S *ctx, HS_PKT_DETAIL_S *detail, void **priv)
{
    char *pIndex = NULL;
    char *pdata_start = NULL;
    char *pSmtp_data = NULL;
    INT32 len = 0;
    int ret;
    SMTP_DATA_INFO *smtp_data = (SMTP_DATA_INFO *)ctx->smtp_info;
    //SMTP_DATA_INFO *smtp_data = &(ctx->smtp_info);
    char tmp[1024] = {0};
    time_t rawtime;
    FILE *fp;
    
    if (detail->tuple.addr.dest != 25)
    {
        return HOOK_ACTION_CONTINUE;
    }

    if( HS_PLUGIN_UNMARKED(ctx, HS_HOOK_POST_DPI, HS_PLUGIN_SMTP)) 
    {
#if 0
        time( &rawtime );
        sprintf(smtp_data->smtp_log_name, "%d%d-%d.log", detail->tuple.addr.saddr, detail->tuple.addr.source, rawtime);
        printf("%s\r\n", smtp_data->smtp_log_name);
#endif		
        HS_PLUGIN_SET_MARKED(ctx, HS_HOOK_POST_DPI, HS_PLUGIN_SMTP);     
    } 

    if (detail->direct == DIR_S2C)
    {
        return HOOK_ACTION_CONTINUE;
    }

    if (smtp_data == NULL)
    {

        smtp_data = (SMTP_DATA_INFO *) hs_malloc(sizeof(SMTP_DATA_INFO));
        if(smtp_data == NULL)
        {
            return HOOK_ACTION_CONTINUE;
        }
        memset(smtp_data, 0, sizeof(SMTP_DATA_INFO));

        ctx->smtp_info = smtp_data;

        
        time( &rawtime );
        sprintf(smtp_data->smtp_log_name, "%d%d-%d", detail->tuple.addr.saddr, detail->tuple.addr.source, rawtime);
        printf("%s\r\n", smtp_data->smtp_log_name);
        
    }

    pSmtp_data = detail->data;

    fp = fopen(smtp_data->smtp_log_name, "a+");
    if (fp == NULL)
    {
            return HOOK_ACTION_CONTINUE;
    }
    fseek(fp, 0L, 2);

    if (smtp_data != NULL && smtp_data->smtp_flag != SMTP_START)
    {
        len = detail->length;;

        ret = dpi_mime_process(pSmtp_data, len, smtp_data, fp);
        if (ret == SMTP_END)
        {
            HS_PLUGIN_SET_UNMARKED(ctx, HS_HOOK_POST_DPI, HS_PLUGIN_SMTP);
    
            HS_SET_DETECT_SUCCESS(ctx->flag);
        }
    }

#if 0
    if ((detail->length > strlen(SMTP_FROM)) && (!strncmp(pSmtp_data, SMTP_FROM, strlen(SMTP_FROM))))
    {
        pdata_start = pSmtp_data + strlen(SMTP_FROM);
        
        if (pdata_start[0] != '<')
        {
            //return HOOK_ACTION_CONTINUE;
            goto PROCESS_END;
        }
        else
        {
            pdata_start ++;
        }
    
        pIndex = strchr(pdata_start, '>');

        if (pIndex > (pSmtp_data + detail->length))
        {
            //return HOOK_ACTION_CONTINUE;
            goto PROCESS_END;
        }

        len = pIndex - pdata_start;

        strncpy(tmp, pdata_start, len);

        tmp[len] = '\0';

        printf("%s\r\n", tmp);
        fprintf(fp, "%s\r\n", tmp);
        
    }
    else if((detail->length > strlen(SMTP_TO)) && (!strncmp(pSmtp_data, SMTP_TO, strlen(SMTP_TO))))
    {
        pdata_start = pSmtp_data + strlen(SMTP_TO);
        
        if (pdata_start[0] != '<')
        {
            //return HOOK_ACTION_CONTINUE;
            goto PROCESS_END;
        }
        else
        {
            pdata_start ++;
        }
    
        pIndex = strchr(pdata_start, '>');

        if (pIndex > (pSmtp_data + detail->length))
        {
            //return HOOK_ACTION_CONTINUE;
            goto PROCESS_END;
        }

        len = pIndex - pdata_start;

        strncpy(tmp, pdata_start, len);

        tmp[len] = '\0';

        printf("%s\r\n", tmp);
        fprintf(fp, "%s\r\n", tmp);
        
    }
#endif    
    if((detail->length > strlen(SMTP_DATA_START)) && (!strncmp(pSmtp_data, SMTP_DATA_START, strlen(SMTP_DATA_START))))
    {
        len = detail->length;
		if(len >= SMTP_BUFF_LEN)
		{
			return 1;
		}
        strncpy(tmp, pSmtp_data, len);
        tmp[len] = '\0';
        printf("%s\r\n", tmp);

        smtp_data ->smtp_flag = SMTP_DATA;
    }    

PROCESS_END:
    
    fclose(fp);
    return HOOK_ACTION_CONTINUE;
}

void dpi_smtp_destroy(void **priv)
{
    return;
}

void DPI_SMTP_DESTROY_CTX_PRIV(void **priv)
{
    if(priv && *priv) {
        hs_free(*priv);
        *priv = NULL;
    }
}

INT32 dpi_smtp_init(void)
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
    ops->priority = HS_PLUGIN_SMTP;
    ops->uDependPluginList = 0;
    ops->bEnable = TRUE;
    ops->fn = dpi_smtp_process;
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