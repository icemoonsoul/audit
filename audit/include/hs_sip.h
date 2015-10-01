#ifndef _HS_SIP_H_
#define _HS_SIP_H_

/**************************************************************************
 * sip plugin
 *************************************************************************/
#define    HS_SIP   	"sip"
#define    HS_RTP   	"rtp"
#define    HS_RTCP   	"rtcp"
#define    HS_PFINGO  	"pfingo"

#define    INVITE_NUM  			6
#define    NUM_200   			6
#define    NUM_183   			20
#define    PORT_LENGTH_MAX 		5
#define    IP_LENGTH_MAX  		15
#define    LENGTH_PORT     		8
#define    LENGTH_IP    		9
#define    REPLY_OFFSET  		8
 
typedef struct HS_sip
{
  struct tuple4 s_tuple;
  INT32 flag;
} HS_sip_t;

enum DETAIL_FLAG {
	HS_INVALID,
	HS_SOURCE,
	HS_DEST,	
	HS_MAX,	
};

INT32 HS_SIP_Init(void);

#endif
