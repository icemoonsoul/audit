#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "hs.h"
#include "hs_consts.h"
#include "hs_core.h"
#include "hs_stat.h"
#include "hs_smtp.h"

#define MIME_BUFF_MAX	128
#define BASE64_MAX		76

const char * base64char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

extern UCHAR *DPI_StrnStr(UCHAR *pucSrc, UCHAR *pucSub, UINT32 uSrcLen);

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

    char ptmp[MIME_BUFF_LEN] = {0};
    unsigned  char pdecode[MIME_BUFF_LEN] = {0};
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

			if(state >= MIME_BUFF_LEN)
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
		if(state >= MIME_BUFF_LEN)
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

INT32 mime_parse_head_method(char *data, int len, MIME_HEAD_INFO_S *pstMime_head_info)
{
    char *pIndex = NULL;
    char *pState = NULL;
    char *pDataLimit = NULL;
    char *pTmp = NULL;
    int flag = 0;
	int limit = 0;

    pDataLimit = data + len;
    pState = data;

	limit = pDataLimit - pState;
    pIndex = DPI_StrnStr(pState, MIME_FROM, limit);
    if(pIndex != NULL)
    {
        pState = pIndex + strlen(MIME_FROM);

		limit = pDataLimit - pState;
        pIndex = DPI_StrnStr(pState, "\r\n", limit);
        if(pIndex == NULL)
        {
            return HS_ERR;
        }
        
        pstMime_head_info->arrInfo[MIME_HEAD_FROM].pucData = pState;
        pstMime_head_info->arrInfo[MIME_HEAD_FROM].uLen = pIndex - pState;

        pState = pIndex + strlen("\r\n");
    }

	limit = pDataLimit - pState;
    pIndex = DPI_StrnStr(pState, MIME_TO, limit);
    if(pIndex != NULL)
    {
        pState = pIndex + strlen(MIME_TO);

        pTmp = pState;
        while(pTmp < pDataLimit)
        {
        	limit = pDataLimit - pTmp;
            pIndex = DPI_StrnStr(pTmp, "\r\n", limit);
            if(pIndex == NULL)
            {
                return HS_ERR;
            }

            if (*(pIndex - 1) != ',' && *(pIndex - 2) != ',')
            {
                flag = 1;
                break;
            }
            else
            {
                flag = 0;
                pTmp = pIndex + strlen("\r\n");
            }
        }
        
        if (flag == 0)
        {
            return HS_ERR;
        }

        pstMime_head_info->arrInfo[MIME_HEAD_TO].pucData = pState;
        pstMime_head_info->arrInfo[MIME_HEAD_TO].uLen = pIndex - pState;

        pState = pIndex + strlen("\r\n");
        
    }

	limit = pDataLimit - pState;
    pIndex = DPI_StrnStr(pState, MIME_SUBJECT, limit);
    if(pIndex != NULL)
    {
        pState = pIndex + strlen(MIME_SUBJECT);

		limit = pDataLimit - pState;
        pIndex = DPI_StrnStr(pState, "\r\n", limit);
        if(pIndex == NULL)
        {
            return HS_ERR;
        }
        
        pstMime_head_info->arrInfo[MIME_HEAD_SUBJECT].pucData = pState;
        pstMime_head_info->arrInfo[MIME_HEAD_SUBJECT].uLen = pIndex - pState;

        pState = pIndex + strlen("\r\n");
    }

    return HS_OK;
}

void Mime_Write_File_Decode(char *data, int len, FILE *fp)
{
	char tmparr[MIME_BUFF_MAX + 1] = {0};
	char decodearr[MIME_BUFF_MAX + 1] = {0};
	int index = 0;
	int limit = 0;
	char *pIndex = NULL;
	
	while(index < len)
	{
		pIndex = DPI_StrnStr(data + index, "\r\n", len - index);
		if (pIndex == NULL)
		{
			if ((len - index) > BASE64_MAX)
			{
				return;
			}

			strncpy(tmparr, data + index, len - index);

			tmparr[len - index] = '\0';
			base64_decode(tmparr, decodearr);
			decodearr[((len-index) * 3) / 4] = '\0';
			fprintf(fp, "%s", decodearr);

			return;
		}
		else
		{
			limit = pIndex - (data + index);
			if (limit != BASE64_MAX)
			{
				return;
			}

			strncpy(tmparr, data + index, BASE64_MAX);
			tmparr[BASE64_MAX] = '\0';
			base64_decode(tmparr, decodearr);
			decodearr[(BASE64_MAX * 3) / 4] = '\0';
			fprintf(fp, "%s", decodearr);

			index += BASE64_MAX + 2;
		}
	}
}

void Mime_Write_File(char *data, int len, FILE *fp)
{
	char tmparr[MIME_BUFF_MAX + 1] = {0};
	int index = 0;
	while(index < len)
	{
		if(MIME_BUFF_MAX < (len - index))
		{
			strncpy(tmparr, data + index, MIME_BUFF_MAX);
			tmparr[MIME_BUFF_MAX] = '\0';
			index += MIME_BUFF_MAX;
			fprintf(fp, "%s", tmparr);
		}
		else
		{
			strncpy(tmparr, data + index, len - index);
			tmparr[len - index] = '\0';
			fprintf(fp, "%s", tmparr);
			return;
		}
	}

	return;
}

void Mime_HeadInfo_Extracted(MIME_HEAD_INFO_S *pstMime_head_info, FILE *fp)
{
	int i = 0;
	char tmparr[MIME_BUFF_MAX] = {0};
	char *pMethod_End;
	char *pState;
	char *pIndex;
	int limit = 0;

	for (i = 0; i < MIME_HEAD_MAX; i++)
	{
		if (pstMime_head_info->arrInfo[i].pucData != NULL)
		{
			if (i == MIME_HEAD_FROM)
			{
				fprintf(fp, "发件人: \r\n");
			}
			else if (i == MIME_HEAD_TO)
			{
				fprintf(fp, "收件人: \r\n");
			}
			else if (i == MIME_HEAD_SUBJECT)
			{
				fprintf(fp, "标题: \r\n");
			}	
		
			pState = pstMime_head_info->arrInfo[i].pucData;
			pMethod_End = pstMime_head_info->arrInfo[i].pucData + pstMime_head_info->arrInfo[i].uLen;
			while (pState < pMethod_End)
			{
				limit = pMethod_End - pState;
				pIndex = DPI_StrnStr(pState, GB2312_KEY, limit);
				if (pIndex == NULL)
				{
					Mime_Write_File(pState, limit, fp);
					break;
				}
				else
				{
					limit = pIndex - pState;
					if (limit != 0)
					{
						Mime_Write_File(pState, limit, fp);
					}

					pState = pIndex + strlen(GB2312_KEY);
					limit = pMethod_End - pState;
					pIndex = DPI_StrnStr(pState, GB2312_END, limit);
					if(pIndex == NULL)
					{
						break;
					}

					limit = pIndex - pState;
					Mime_Write_File_Decode(pState, limit, fp);

					pState = pIndex + strlen(GB2312_END);
				}
			}
		}
		fprintf(fp, "\r\n");
	}

	return;
}

INT32 mime_head_process(char *data, int len, MAIL_DATA_INFO *psmtpInfo, FILE *fp)
{
	int ret = 0;
	MIME_HEAD_INFO_S stMime_head_info;
	memset(&stMime_head_info, 0, sizeof(MIME_HEAD_INFO_S));
	
    ret = mime_parse_head_method(data, len, &stMime_head_info);
	if (ret != HS_OK)
	{
		return HS_ERR;
	}

	Mime_HeadInfo_Extracted(&stMime_head_info, fp);

    return HS_OK;
}

INT32 mime_body_process(char *data, int len, MAIL_DATA_INFO *psmtpInfo, FILE *fp)
{
	char *pIndex = NULL;
	char *pState = NULL;
	char *pDataLimit = NULL;
	int limit = 0;

	pState = data;
	pDataLimit = pState + len;

	if (psmtpInfo->mail_flag == MIME_BODY)
	{
		pIndex = smtp_data_move(pState, pDataLimit, MIME_CONTENT_KEY);
		if (pIndex == NULL)
		{
			return HS_ERR;
		}

		psmtpInfo->mail_flag = MIME_CONTENT;
		pState = pIndex;
	}

	if (psmtpInfo->mail_flag == MIME_CONTENT)
	{
		pIndex = smtp_data_move(pState, pDataLimit, MIME_TEXT_ENCODE);
		if (pIndex == NULL)
		{
			return HS_ERR;
		}

		if(!strncmp(pIndex, BASE64_KEY, strlen(BASE64_KEY)))
		{
			psmtpInfo->base64_flag = MIME_CONTENT_BASE64;
		}
		else
		{
			psmtpInfo->base64_flag = MIME_CONTENT_NOBASE64;
		}

		psmtpInfo->mail_flag = MIME_CONTENT_ENCODE;
		pState = pIndex;
	}

	if (psmtpInfo->mail_flag == MIME_CONTENT_ENCODE)
	{
		pIndex = smtp_data_move(pState, pDataLimit, MIME_PART_KEY);
		if (pIndex == NULL)
		{
			return HS_OK;
		}

		psmtpInfo->mail_flag = MIME_CONTENT_START;

		fprintf(fp, "邮件正文: \r\n");

		pState = pIndex;
	}

	if (psmtpInfo->mail_flag == MIME_CONTENT_START)
	{
		pIndex = DPI_StrnStr(pState, MIME_PART_KEY, pDataLimit - pState);
		if (pIndex == NULL)
		{
			limit = pDataLimit - pState;
			
		}
		else
		{
			limit = pIndex - pState;
			psmtpInfo->mail_flag = MIME_CONTENT_END;
		}

		if (psmtpInfo->base64_flag == MIME_CONTENT_BASE64)
		{
			Mime_Write_File_Decode(pState, limit, fp);
		}
		else if (psmtpInfo->base64_flag == MIME_CONTENT_NOBASE64)
		{
			Mime_Write_File(pState, limit, fp);
		}
	}

	return HS_OK;
}

INT32 HS_Mime_Process(char *data, int len, MAIL_DATA_INFO *psmtpInfo, FILE *fp)
{
    char *pdata_end = NULL;
    char *pIndex = NULL;
    char *pStart = NULL;
    char *pEnd = NULL;
    int ret = 0;;
    int state = 0;
	int limit = 0;

    char ptmp[128] = {0};
    unsigned  char pdecode[128] = {0};
    int base64 = 0;

    pStart = data;
    pdata_end = data + len;

    if (data == NULL || psmtpInfo == NULL || fp == NULL)
    {
        return MIME_END;
    }

	limit = pdata_end - data;
	
    pIndex = DPI_StrnStr(data, SMTP_DATA_END, limit);
    if(pIndex != NULL)
    {
        ret = MIME_END;
    }

    if(psmtpInfo->mail_flag == MIME_HEAD)
    {
        mime_head_process(data, len, psmtpInfo, fp);
		psmtpInfo->mail_flag = MIME_BODY;
    }

	if(psmtpInfo->mail_flag == MIME_BODY)
	{
		mime_body_process(data, len, psmtpInfo, fp);
	}

	return ret;
}

INT32 HS_Smtp_Process(HS_CTX_S *ctx, HS_PKT_DETAIL_S *detail, void **priv)
{
    char *pIndex = NULL;
    char *pdata_start = NULL;
    char *pSmtp_data = NULL;
    INT32 limit = 0;
    int ret;
    MAIL_DATA_INFO *pstMail_info = ctx->pstMail_info;
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
        sprintf(smtp_data->mail_log_name, "%d%d-%d.log", detail->tuple.addr.saddr, detail->tuple.addr.source, rawtime);
        printf("%s\r\n", smtp_data->mail_log_name);
#endif	
		//ctx->pstMail_info = pstMail_info = NULL;
        HS_PLUGIN_SET_MARKED(ctx, HS_HOOK_POST_DPI, HS_PLUGIN_SMTP);     
    } 

    if (detail->direct == DIR_S2C)
    {
        return HOOK_ACTION_CONTINUE;
    }
	
	pSmtp_data = detail->data;


    if (pstMail_info != NULL && pstMail_info->mail_flag != MIME_NONE)
    {
	    fp = fopen(pstMail_info->mail_log_name, "a+");
	    if (fp == NULL)
	    {
	            return HOOK_ACTION_CONTINUE;
	    }
	    fseek(fp, 0L, 2);
		
        limit = detail->length;;

        ret = HS_Mime_Process(pSmtp_data, limit, pstMail_info, fp);
        if (ret == MIME_END)
        {
            HS_PLUGIN_SET_UNMARKED(ctx, HS_HOOK_POST_DPI, HS_PLUGIN_SMTP);
    
            HS_SET_DETECT_SUCCESS(ctx->flag);
        }

		fclose(fp);
		goto PROCESS_END;
    }

    if((detail->length > strlen(SMTP_DATA_START)) && (!strncmp(pSmtp_data, SMTP_DATA_START, strlen(SMTP_DATA_START))))
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

INT32 HS_Smtp_Init(void)
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
    ops->fn = HS_Smtp_Process;
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
