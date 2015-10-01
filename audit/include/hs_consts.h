#ifndef __HS_CONSTS_H_
#define __HS_CONSTS_H_

#define CR                              '\r'
#define LF                              '\n'

#define TCP_PROTOCOL		            6
#define UDP_PROTOCOL		            17

#define MAX_BUFF_LEN                    64
#define MAX_BUFF_LEN_1K                 1024
#define MAX_BUFF_LEN_256                256
#define INI_BUFF_LEN                    1048576
#define DNS_BUFF_LEN                    256

#define MAX_ID_NUM	                    16

#define RULE_ID_MAX                     16

/* max protocols in one group protocol */
#define MAX_APP                         256
#define MAX_DFA                         256

#define MIN_SIG_PRIORITY	            (-5)

#define DFA_PER_TYPE_MAX                64

#define HS_HOST_HASH_INDEX_DEFAULT		((UINT32)~0)

/* the max versions in one protocol */
#define MAX_VERSION                     16	

#define UNKNOWN_DFA_ID  	            ((UINT32)~0)

#define DEFAULT_CHILDREN_NUM	        16

#define HS_CNT_ENCRYPT_SCAN_COUNT	    10
#define HS_CNT_SIP_SCAN_COUNT		    20
#define HS_CNT_SCAN_COUNT			    20
#define HS_CNT_SCAN_COUNT_MIN		    10
#define HS_CNT_SCAN_LENGTH_PER_PKT      0
#define HS_MAX_SCAN_COUNT			    128

#define DFI_MAX_SCAN_COUNT			    64
#define DFI_RADIO_PKT_SAVE_NUM		    8

#define HS_MAX_TS_DELTA			        300		/* (seconds) */
#define HS_PBDL_MAX_EVENT_NUM 		    8
#define HS_MAX_ASSOCIATE_NUM 		    64

/* add for len + tuple + content scan  begin */
#define HS_DFA_PKT_LEN				    2
#define HS_DFA_PROTOCOL_LEN		        1
#define HS_DFA_SPORT_LEN			    2
#define HS_DFA_DPORT_LEN			    2
#define HS_DFA_SADDR_LEN			    4
#define HS_DFA_DADDR_LEN			    4

#define HS_MAX_P2P_NUM					128
#define HS_MAX_HTTP_MULTI_NUM			16
#define HS_MAX_DNS_NUM     		        32     
#define HS_MAX_FAKE_NUM				    16
#define HS_PBDL_MAX_APP_NUM 			64

#define HS_CONTENT_SCAN_DATA_LENTH 	    256

#define MAX_UDP_EFFECTIVE_PKT_NUM	    5

#define CHECK_LIB_TIME_LIMIT_RATE		(1 << 30)

#endif
