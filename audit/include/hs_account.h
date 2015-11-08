#ifndef _HS_ACCOUNT_H_
#define _HS_ACCOUNT_H_

#include "hs_types.h"

#define ACCOUNT_MAX_LEN				32
#define ACCOUNT_ACTION_LEN          20

#define ACCOUNT_SACN_SMTPNUM_MAX    20
#define ACCOUNT_SACN_POP3NUM_MAX    6

#define DPI_WEIXIN_MOBILE			"wei-xin-mobile_1"
#define DPI_WEIXIN_MOBILE_2			"wei-xin-mobile_2"
#define DPI_QQ_CHAT_MOBILE			"qq-chat-mobile_3"
#define DPI_QQ_CHAT					"qq-chat_5"
#define DPI_SINA_WEIBO_LOGIN		"sina-wei-bo_12_login"
#define DPI_WANG_WANG_CHAT		    "wang-wang-chat"
#define DPI_FETION_LOGIN		    "fetion-chat_2_login"
#define DPI_126MAIL_LOGIN           "wang-yi-126-mail_4_login"
#define DPI_126MAIL_SEND            "wang-yi-126-mail_5_send"
#define DPI_163MAIL_LOGIN           "wang-yi-163-mail_5_login"
#define DPI_163MAIL_SEND            "wang-yi-163-mail_6_send"
#define DPI_BAIDU_LOGIN             "bai-du-pc-app-login_1"
#define DPI_WANGYIWEIBO_LOGIN   	"wang-yi-wei-bo_1"
#define DPI_DOUBAN_LOGIN   		    "dou-ban_3"
#define DPI_SMTP_ACC                "smtp"
#define DPI_POP3_ACC                "pop3"
#define DPI_MAOPU_LOGIN				"mao-pu-deng-lu_1"
#define DPI_MAOPU_BROWSER			"mao-pu-liu-lan_1"
#define DPI_TENCENT_WEIBO_BROWSER	"teng-xun-wei-bo_1_browser"
#define DPI_TENCENT_WEIBO_POSTS		"teng-xun-wei-bo_2_post"
#define DPI_RENREN_LOGIN			"ren-ren_2"

#define  VIRACC_ACTION_LOGIN 		"login"
#define  VIRACC_ACTION_LOGINOUT		"loginout"
#define  VIRACC_ACTION_BROWSER		"browser"
#define  VIRACC_ACTION_POSTS		"post"
#define  VIRACC_ACTION_SENDMAIL		"send mail"
#define  VIRACC_ACTION_RECIVCEMAIL	"receive mail"
#define  VIRACC_ACTION_SENDMSG		"send msg"
#define  VIRACC_ACTION_RECIVCEMSG	"receive msg"	
#define  VIRACC_ACTION_WATCAVIDEO 	"watch video"

enum
{
	VA_MAIL = 1,
	VA_NUM,
	VA_NICKNAME
};

typedef enum _app_virtacc_action
{
	VIRTACC_LOGIN,
	VIRTACC_LOGIN_OUT,
	VIRTACC_BROWSER,
	VIRTACC_POSTS,
	VIRTACC_SEND_MAIL,
	VIRTACC_RECIVCE_MAIL,
	VIRTACC_SEND_MGS,
	VIRTACC_RECIVCE_MSG,
	VIRTACC_WATCH_VIDEO,
	VIRTACC_OTHER
} APP_VIRTACC_ACTION_E;


/* content audit type */
typedef enum {
    ACCOUNT_WEIXIN_MOBILE,
    ACCOUNT_QQ_CHAT,
    ACCOUNT_QQ_CHAT_SENDMSG,
    ACCOUNT_SINA_WEI_BO,
    ACCOUNT_WANG_WANG_CHAT,
    ACCOUNT_FETION,
    ACCOUNT_BAIDU_LOGIN,
    ACCOUNT_126MAIL_LOGIN,
    ACCOUNT_126MAIL_SEND,
    ACCOUNT_163MAIL_LOGIN,
    ACCOUNT_163MAIL_SEND,
    ACCOUNT_WANGYIWEIBO_LOGIN,
    ACCOUNT_DOUBAN_LOGIN,
    ACCOUNT_SMTP,
    ACCOUNT_POP3,
    ACCOUNT_MAOPU_LOGIN,
    ACCOUNT_MAOPU_BROWSER,
    ACCOUNT_TENCENT_WEIBO_BROWSER,
    ACCOUNT_TENCENT_WEIBO_POSTS,
    ACCOUNT_RENREN_LOGIN,
    ACCOUNT_MAX,
} DPI_ACCOUNT_E;

typedef enum {
    ACCOUNT_HOOK_WEIXIN_MOBILE,
	ACCOUNT_HOOK_WEIXIN_MOBILE_2,
    ACCOUNT_HOOK_QQ_MOBILE,
    ACCOUNT_HOOK_QQ,
    ACCOUNT_HOOK_SINA_WEI_BO,
    ACCOUNT_HOOK_WANG_WANG,
    ACCOUNT_HOOK_FETION,
    ACCOUNT_HOOK_BAIDU,
    ACCOUNT_HOOK_126MAIL,
    ACCOUNT_HOOK_163MAIL,
    ACCOUNT_HOOK_WANGYI_WEI_BO,
    ACCOUNT_HOOK_DOUBAN,
    ACCOUNT_HOOK_SMTP,
    ACCOUNT_HOOK_POP3,
    ACCOUNT_HOOK_MAOPU,
    ACCOUNT_HOOK_TENCENT_WEI_BO,
    ACCOUNT_HOOK_RENREN,
    ACCOUNT_HOOK_MAX
} ACCOUNT_HOOK_E;

typedef enum {
    ACCOUNT_GET_FIRST = 0,
    ACCOUNT_GET_OTHER = 1,

    ACCOUNT_GET_MAX
} ;


typedef struct app_account {
    DPI_ACCOUNT_E		 account_type;
	CHAR                 flag;
	CHAR 				 account_buff[ACCOUNT_MAX_LEN];
} APP_ACCOUNT_S;

int HS_Account_Init(void);

#define   APP_NAME_MAXLEN  64
#define   ACCOUNT_BUF_LEN  32
#define   ACCOUNT_MAX_LEN  32

#define   ACCOUNT_SCAN_MAXNUM  1000


#define   ACCOUNT_NODE_NUM  1000

#define   ACCOUNT_READBUF_LEN   256

#define   ACCOUNT_DESCRIP_FILE   "..\account.ini"


/*账号合法性检查类型*/
enum 
{
	ACCOUNT_CHECK_MIN = 0,
	ACCOUNT_CHECK_EMAIL = 1,
	ACCOUNT_CHECK_NUMBER,
	ACCOUNT_CHECK_GENERAL,
	ACCOUNT_CHECK_MAX,
};

typedef struct 
{
	CHAR      name[APP_NAME_MAXLEN];           /*应用名称*/
    CHAR      sig_start[ACCOUNT_BUF_LEN];      /*账号起始标志字符串*/
    CHAR      sig_end;                         /*账号结束标志字符*/
    CHAR      str_find[ACCOUNT_BUF_LEN];       /*待替换字符*/
    CHAR      str_replace[ACCOUNT_BUF_LEN];    /*替换字符*/
    //CHAR      str_append[ACCOUNT_BUF_LEN];     /*末尾追加的字符串*/
    
    UINT32    sig_end_seq;                     /*结束标志字符序号*/
    UINT32    len_min;                         /*账号最小长度*/
    UINT32    len_max;                         /*账号最大长度*/
	UINT32    check_type;                      /*账号合法性检查类型*/
    UINT32    appid;                           /*APP ID*/
    UINT32    sig_start_len;                   /*账号起始字符串长度*/
} ACCOUNT_NODE_ASCII_S;

typedef struct 
{
	CHAR      name[APP_NAME_MAXLEN];           /*应用名称*/
    CHAR      sig_start[ACCOUNT_BUF_LEN];      /*账号起始标志字符串*/
    CHAR      sig_end;                         /*账号结束标志字符*/
    CHAR      str_find[ACCOUNT_BUF_LEN];       /*待替换字符*/
    CHAR      str_replace[ACCOUNT_BUF_LEN];    /*替换字符*/
    //CHAR      str_append[ACCOUNT_BUF_LEN];     /*末尾追加的字符串*/
    
    UINT32    sig_end_seq;                     /*结束标志字符序号*/
    UINT32    len_min;                         /*账号最小长度*/
    UINT32    len_max;                         /*账号最大长度*/
	UINT32    check_type;                      /*账号合法性检查类型*/
    UINT32    appid;                           /*APP ID*/
    UINT32    sig_start_len;                   /*账号起始字符串长度*/
} ACCOUNT_NODE_HEX_S;


#endif
