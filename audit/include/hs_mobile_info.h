#ifndef _HS_MOBILE_INFO_H_
#define _HS_MOBILE_INFO_H_

#include "hs_types.h"

#define MOBLIE_APP_NAME_MAXLEN		32
#define SIG_BUF_LEN          		16


#define IMEI_INFO_MAX				16
#define IMSI_INFO_MAX				16
#define PHONE_INFO_MAX				16
#define MOBILE_INFO_NODE_MAX 		64

#define HS_SET_MOBILE_INFO_MARKED(flag, move)			((flag) |= (1 << move))
#define HS_TEST_MOBILE_INFO_MARKED(flag, move)			(flag & 1 << move)



typedef enum {
		IMEI_FLAG,
		IMSI_FLAG,
		PHONE_FLAG,
		MAX_FLAG,
} DPI_MOBILE_INFO_E;

typedef enum {
		CONTINUE_PARSER,
		BREAK_PARSER,
} DPI_PARSER_ACTION_E;


typedef struct mobile_info_node
{
	CHAR      name[MOBLIE_APP_NAME_MAXLEN];         /*应用名称*/
    CHAR      sig_start[SIG_BUF_LEN];      			/*账号起始标志字符串*/
    CHAR      sig_end;       				   		/*账号结尾字符*/
	DPI_MOBILE_INFO_E	type_info;
	DPI_PARSER_ACTION_E	parser_action;
	CHAR	  mark_flag;
	UINT32    appid;                           		/*APP ID*/
} MOBILE_INFO_NODE_S;

typedef struct mobile_info {
	CHAR 				 IMEI_buff[IMEI_INFO_MAX];
	CHAR 				 IMSI_buff[IMSI_INFO_MAX];
	CHAR 				 PHONE_buff[PHONE_INFO_MAX];
	CHAR                 info_type_flag;
} MOBILE_INFO_S;


#endif


