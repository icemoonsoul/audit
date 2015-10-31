#ifndef __DPI_SMTP_H_
#define __DPI_SMTP_H_

#define     DPI_SMTP        "smtp"

#define     GB2312_KEY      "=?gb2312?B?"
#define     GB2312_END      "?="
#define     BASE64_KEY      "base64"

#define     SMTP_FROM                     "MAIL FROM: "
#define     SMTP_TO                         "RCPT TO: "
#define     SMTP_DATA_START         "DATA"
#define     SMTP_DATA_END             "\r\n.\r\n"

#define     POP3_RETR_START         "RETR"


#define     MIME_FROM                         "From: "
#define     MIME_TO                             "To: "
#define     MIME_SUBJECT                    "Subject: "
#define     MIME_CONTENT_KEY                "Content-Type: text/plain"
#define 	MIME_PART_KEY				"\r\n\r\n"
#define     MIME_TEXT_ENCODE            "Content-Transfer-Encoding: "

#define     MIME_END    3

#define 	MIME_CONTENT_BASE64 1
#define 	MIME_CONTENT_NOBASE64 0

typedef struct mail_data_info
{
    int mail_flag;
	int base64_flag;
    char mail_log_name[64];
}MAIL_DATA_INFO;

enum SMTP_FLAG {
	MIME_NONE,
	MIME_HEAD,
	MIME_BODY,
	MIME_CONTENT,
	MIME_CONTENT_ENCODE,
	MIME_CONTENT_START,
	MIME_CONTENT_END,
	SMTP_MAX,	
};

enum MIME_HEAD_METHOD {
        MIME_HEAD_FROM,
        MIME_HEAD_TO,
        MIME_HEAD_SUBJECT,
        MIME_HEAD_MAX,
};

typedef struct mime_field_info {
    UCHAR *pucData;    UINT32 uLen;} MIME_FIELD_INFO_S;

typedef struct mime_head {
    MIME_FIELD_INFO_S arrInfo[MIME_HEAD_MAX];
} MIME_HEAD_INFO_S;


#endif
