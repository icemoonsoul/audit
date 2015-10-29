#ifndef __DPI_SMTP_H_
#define __DPI_SMTP_H_

#define     DPI_SMTP        "smtp"

#define     GB2312_KEY      "=?GB2312?B?"
#define     GB2312_END      "?="
#define     BASE64_KEY      "base64"

#define     SMTP_FROM                     "MAIL FROM: "
#define     SMTP_TO                         "RCPT TO: "
#define     SMTP_DATA_START         "DATA"
#define     SMTP_DATA_END             "\r\n.\r\n"

#define     MIME_FROM                         "From: "
#define     MIME_TO                             "To: "
#define     MIME_SUBJECT                    "Subject: "
#define     MIME_CONTENT                   "Content-Type: text/plain"
#define     MIME_TEXT_ENCODE            "Content-Transfer-Encoding: "

#define     SMTP_END    3

#define		SMTP_BUFF_LEN	128

typedef struct smtp_data_info
{
    int smtp_flag;
    char smtp_log_name[64];
}SMTP_DATA_INFO;

enum SMTP_FLAG {
	SMTP_START,
	SMTP_DATA,
	MIME_FROM_START,
	MIME_FROM_END,
	MIME_TO_START,
	MIME_TO_END,
	MIME_SUBJCT_START,
	MIME_SUBJCT_END,
	MIME_CONTENT_START,
	MIME_ENCODE_START,
	MIME_ENCODE_END,
	MIME_CONTENT_END,
	SMTP_MAX,	
};


#endif