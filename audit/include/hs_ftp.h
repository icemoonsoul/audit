#ifndef _HS_FTP_H_
#define _HS_FTP_H_

#define HS_FTP_PORT_IPV4 		"PORT"
//#define HS_FTP_PORT_IPV6 "EPRT"
#define HS_FTP_PASV_IPV4 		"PASV"
#define HS_FTP_PASV_IPV6 		"EPSV"
#define HS_FTP_LOG 			    "230 User logged in"
#define HS_FTP_PORTOK1 		    "200 PORT"
#define HS_FTP_PORTOK2 		    "200 Port"
#define HS_FTP_PASVOK 			"227"
#define HS_FTP_PASVOK_IPV6 	    "229 Entering Extended Passive Mode"

enum FTP_STATE {
	HS_FTP_INVALID = 0,
	HS_FTP_LOGIN,
	HS_FTP_PORT_REQ,
	HS_FTP_PORT_OK,
	HS_FTP_PASV_REQ,
	HS_FTP_PASV_OK,
	HS_FTP_MAX
};
	
typedef struct ftp_data
{
	enum FTP_STATE state;
	UINT16 port;
} ftp_data_st;

INT32 HS_FTP_Init(void);

#endif
