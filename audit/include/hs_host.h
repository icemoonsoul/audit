#ifndef _HS_HOST_H_
#define _HS_HOST_H_

/**************************************************************************
 * host plugin
 *************************************************************************/
#define HOST_PORT_DELTA							32
#define HOST_PORT_MIN							1024
#define HOST_MAX_PORT_NUM						8
#define HS_HOST_TS_TIMEOUT						600000	//10m
#define HS_APP_TS_TIMEOUT						300000	//3//5m

#define HS_MIN_MATCH_PORT_COUNT 				5

//#define HOST_TIMEOUT_MAX_DEL  1024    
#define HOST_TIMEOUT_MAX_DEL 					256  
#define MAX_HOST_APP_PORT_NUM  					7

#define HS_MAX_HOST_NUM 						200000
#define HS_HOST_INCLUDE_MAX_APP_NUM            8
#define MAX_TCP_PORT_PAIR_EACH_HOST				16
#define MAX_UDP_NODE_EACH_HOST					16

/* modify host_module memory use from nos_malloc to chunk_malloc begin */
#define HS_HOST_MAX_HOST_NUMS 					200000
#define HS_HOST_MAX_HOST_APP_NUMS 				(8*HS_HOST_MAX_HOST_NUMS)
#define HS_HOST_MAX_HOST_APP_TCP_PORT 			(8*8*HS_HOST_MAX_HOST_NUMS)
#define HS_HOST_MAX_HOST_APP_UDP_PORT 			(8*8*HS_HOST_MAX_HOST_NUMS)
/* modify host_module memory use from nos_malloc to chunk_malloc end */

typedef struct _port_pair {
	UINT32 uAppId;
	UINT16 usMinPort;
	UINT16 usMaxPort;
} HOST_PORT_PAIR_S;

typedef struct _host_udp_node {
	UINT32 uAppId;
	UINT16 usPort;
} HOST_UDP_NODE_S;

#define PORT_IS_MATCHED(pstPortPair, usPort) ((usPort) >= (pstPortPair)->usMinPort && \
	    (usPort) <= (pstPortPair)->usMaxPort)

#define HOST_IS_DEFAULT_HASH_INDEX(pstCtx) 	((pstCtx)->uHostHashIndex == HS_HOST_HASH_INDEX_DEFAULT)

static inline void UPDATE_PORT_PAIR(HOST_PORT_PAIR_S *pstPair, UINT32 uAppId, UINT16 usPort) 
{
	pstPair->uAppId = uAppId;
	pstPair->usMinPort = (pstPair->usMinPort < (usPort - HOST_PORT_DELTA) ? pstPair->usMinPort : usPort - HOST_PORT_DELTA);
   	pstPair->usMaxPort = (pstPair->usMaxPort > (usPort + HOST_PORT_DELTA) ? pstPair->usMaxPort : usPort + HOST_PORT_DELTA);
}

typedef struct _pbdl_event {
	UINT32	uEventId;
	INT32	nPriority;
	UINT32 	stTsDelta;		
	BOOL 	bEnable;
	HS_time_t stTimeOut;
} PBDL_EVENT_S;

typedef struct host {
	HS_rwlock_t rwlock;
	UINT32 uHashIndex;
	UINT32 ipaddr;
	UINT16 usTcpPortGuard;
	UINT16 usUdpNodeGuard;
	UINT16 usEventGuard;
	UINT16 uSkypeLogin:1;          	/*for skype */
	HOST_PORT_PAIR_S arrstTcpPortPair[MAX_TCP_PORT_PAIR_EACH_HOST];
	HOST_UDP_NODE_S arrstUdpNode[MAX_UDP_NODE_EACH_HOST];
	UINT32 uLastP2pApp;
	struct list_head timeout_list;
	HS_time_t ts;						/* lastest update time stamp */
	UINT32 uEventNum;
	PBDL_EVENT_S arrstEvent[HS_PBDL_MAX_EVENT_NUM]; 	/* for PBDL Event */
} HS_HOST;

typedef HS_HOST HS_HOST_S;

typedef HS_HOST HS_HOST_OBJ_S;

static inline void INIT_HS_HOST(HS_HOST_S *pstHost)
{
	if(pstHost) {
		memset(pstHost, 0, sizeof(HS_HOST_S));
		HS_rwlock_init(&pstHost->rwlock);
		INIT_LIST_HEAD(&pstHost->timeout_list);
		pstHost->uLastP2pApp = UNKNOWN_ID;
	}		

	return;
}

static inline void HOST_ADD_TCP_PORT_PAIR(HS_HOST_S *pstHost, UINT32 uAppId, UINT16 usPort)
{
	if (pstHost->usTcpPortGuard >= MAX_TCP_PORT_PAIR_EACH_HOST) {
		HS_WARN("HOST: Tcp-port-guard exceeds to the upper limit.\n");
		pstHost->usTcpPortGuard = 0;
		return;
	}
	
	pstHost->arrstTcpPortPair[pstHost->usTcpPortGuard].uAppId = uAppId;
	pstHost->arrstTcpPortPair[pstHost->usTcpPortGuard].usMinPort = usPort - HOST_PORT_DELTA;
	pstHost->arrstTcpPortPair[pstHost->usTcpPortGuard].usMaxPort = usPort + HOST_PORT_DELTA;

	/* Maybe there would be a lock. */
	if (pstHost->usTcpPortGuard >= MAX_TCP_PORT_PAIR_EACH_HOST - 1) {
		pstHost->usTcpPortGuard = 0;
	} else {
		pstHost->usTcpPortGuard++;
	}
}

static inline void HOST_UPDATE_TCP_PORT_PAIR(HS_HOST_S *pstHost, UINT32 uAppId, UINT16 usPort)
{
	UINT32 idx;

	HS_write_lock(&pstHost->rwlock);

	for(idx = 0; idx < MAX_TCP_PORT_PAIR_EACH_HOST; idx++) {
		if(PORT_IS_MATCHED(&pstHost->arrstTcpPortPair[idx], usPort)) {
			UPDATE_PORT_PAIR(pstHost->arrstTcpPortPair + idx, uAppId, usPort);
			goto END;
		}
	}

	HOST_ADD_TCP_PORT_PAIR(pstHost, uAppId, usPort);

END:
	HS_write_unlock(&pstHost->rwlock);

	return;
}

static inline void HOST_ADD_UDP_NODE(HS_HOST_S *pstHost, UINT32 uAppId, UINT16 usPort)
{
	if (pstHost->usUdpNodeGuard >= MAX_UDP_NODE_EACH_HOST) {
		HS_WARN("HOST: Udp-port-guard exceeds to the upper limit.\n");
		pstHost->usUdpNodeGuard = 0;
		return;
	}
	
	pstHost->arrstUdpNode[pstHost->usUdpNodeGuard].uAppId = uAppId;
	pstHost->arrstUdpNode[pstHost->usUdpNodeGuard].usPort = usPort;

	/* Maybe there would be a lock. */
	if (pstHost->usUdpNodeGuard >= MAX_UDP_NODE_EACH_HOST - 1) {
		pstHost->usUdpNodeGuard = 0;
	} else {
		pstHost->usUdpNodeGuard++;
	}
}

static inline void HOST_UPDATE_UDP_NODE(HS_HOST_S *pstHost, UINT32 uAppId, UINT16 usPort)
{
	UINT32 idx;

	for(idx = 0; idx < MAX_UDP_NODE_EACH_HOST; idx++) {
		if(pstHost->arrstUdpNode[idx].usPort == usPort) {
			return;
		}
	}

	HS_write_lock(&pstHost->rwlock);
	HOST_ADD_UDP_NODE(pstHost, uAppId, usPort);
	HS_write_unlock(&pstHost->rwlock);

	return;
}

static inline void UPDATE_HOST_TS(HS_HOST_S *pstHost, HS_PKT_DETAIL_S *pstDetail)
{
	pstHost->ts = pstDetail->ts;	
}

typedef struct _host_probe_info {
	HS_CTX_S *pstCtx;		
	HS_PKT_DETAIL_S *pstDetail;
	UINT32 uInnerIp;
	UINT16 usInnerPort;
} HOST_PROBE_INFO_S;

static inline UINT32 hash_host(void *pstHost) {
	if( !pstHost)
		return 0;
	
	return HASH_INT32((INT32 *)&((HS_HOST_S *)pstHost)->ipaddr);			
}

void *AllocHost(void *data);

INT32 HS_HOST_Init(HS_DATA_S *dpi);

#endif
