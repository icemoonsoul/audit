#include <string.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <util.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "nids.h"
#include "hs_consts.h"
#include "hs.h"
#include "zlog.h"

#define VERSION_MASK                0x000000ffUL
#define MASK_VERSION(id)            ((id) & (~VERSION_MASK))

extern LANG_TYPE g_enLang;
extern CHAR g_arrcLibFile[MAX_BUFF_LEN];
zlog_category_t *g_pstZc = NULL;
struct nids_chksum_ctl *chksum_ctl;

static void HS_udp_process_data(struct udp_stream *udp, void **priv);

void dump_tuple5(INT32 protocol, struct tuple4 *addr, UINT32 app_id, const CHAR *app_name,  UINT32 proc_count)
{
    CHAR saddr_str[16];
    CHAR daddr_str[16];
    CHAR protocol_str[16];
    struct in_addr saddr;
    struct in_addr daddr;
    
    if(!addr)
        return;

    saddr.s_addr = ntohl(addr->saddr);

    strcpy(saddr_str, inet_ntoa(saddr));

    daddr.s_addr = ntohl(addr->daddr);
    strcpy(daddr_str, inet_ntoa(daddr));
    
    if (protocol == TCP_PROTOCOL) {
        strcpy(protocol_str, "TCP");
    } else if (protocol == UDP_PROTOCOL) {
        strcpy(protocol_str, "UDP");
    } else {
        strcpy(protocol_str, "Unknown");
    }

    //HS_PRINT("%8s%18s%18s%14d%14d    %23s%16d\n\n", protocol_str, saddr_str, daddr_str, 
    //  (addr->source), (addr->dest), app_name, proc_count);

#ifdef HS_PRINTT_STAT
    HS_PRINT("%8s%18s%18s%14d%14d    %23s\n\n", protocol_str, saddr_str, daddr_str, \
        (addr->source), (addr->dest), app_name);
#endif    
    return;
}

static void HS_tcp_create_session(struct tcp_stream *tcp, void **priv)
{
	tcp->server.collect++;
	tcp->client.collect++;

	return;
}

static void HS_tcp_process_data(struct tcp_stream *tcp, void **priv)
{
	HS_PKT_DETAIL_S stDetail;
	UINT32  uNeedPrint = 1;
	UINT32 appid;
	UINT32 probe_count;
	CHAR buff[64];
    HS_CTX_S *pstCtx = *(HS_CTX_S **)priv;

    if (pstCtx == NULL) {
        return; 
    }

	stDetail.tuple.protocol = TCP_PROTOCOL;
	stDetail.tuple.addr = tcp->addr;
	stDetail.ts = g_latest_ts;

	/* no necessary to detect. */
	if (HS_CTX_SUCCESS(pstCtx)) {
		if (!HS_CTX_MARKED(pstCtx)) {
            tcp->bypass = 1;
            *priv = NULL;
            HS_DestroyCtx(pstCtx);
            free(pstCtx);
			return;
		} else {
			uNeedPrint = 0;
		}
	}

	if (tcp->server.count_new) {
		/* client -> server */
		stDetail.direct = DIR_C2S;
		stDetail.data = (UCHAR *)tcp->server.data;
		stDetail.length = tcp->server.count_new;
	} else if(tcp->client.count_new) {
		/* server -> client */
		stDetail.direct = DIR_S2C;
		stDetail.data = (UCHAR *)tcp->client.data;
		stDetail.length = tcp->client.count_new;
	}

	HS_Probe(pstCtx, &stDetail);

	if (uNeedPrint > 0 && HS_CTX_SUCCESS(pstCtx)) {
		appid = HS_GetAppIdFromCtx(pstCtx);
		probe_count = HS_GetProbeCount(pstCtx);
		HS_FindAppNameByAppId(MASK_VERSION(appid), g_enLang, buff, 64);
		dump_tuple5(TCP_PROTOCOL, &tcp->addr, appid, buff, probe_count);
	}

}

static void HS_tcp_close_session(struct tcp_stream *tcp, void **priv)
{
	UINT32 appid;
	UINT32 probe_count;
	CHAR buff[64];
    HS_CTX_S *pstCtx = *(HS_CTX_S **)priv;
    
    if (pstCtx == NULL) {
        return; 
    }

	appid = HS_GetAppIdFromCtx(pstCtx);
	probe_count = HS_GetProbeCount(pstCtx);

	if (!HS_CTX_SUCCESS(pstCtx)) {
		if (HS_IsUnknownId(appid)) {
			HS_IncAppCount(g_uAppOther);
            HS_IncAppTrafficCount(g_uAppOther, tcp->client.traffic_count + tcp->server.traffic_count);
			HS_FindAppNameByAppId(MASK_VERSION(g_uAppOther), g_enLang, buff, 64);
			dump_tuple5(TCP_PROTOCOL, &tcp->addr, appid, buff, probe_count);
		} else {
			assert(HS_CTX_MARKED(pstCtx));
            appid = MASK_VERSION(appid);
            
			HS_IncAppCount(appid);
            HS_IncAppTrafficCount(appid, tcp->client.traffic_count + tcp->server.traffic_count);
			HS_FindAppNameByAppId(appid, g_enLang, buff, 64);
			dump_tuple5(TCP_PROTOCOL, &tcp->addr, appid, buff, probe_count);
		}
	} else {
		if (HS_CTX_MARKED(pstCtx)) {
			HS_IncAppCount(appid);
		}

        HS_IncAppTrafficCount(appid, tcp->client.traffic_count + tcp->server.traffic_count);
	}
	
	HS_DestroyCtx(pstCtx);

    free(pstCtx);
}

static void tcp_callback(struct tcp_stream *tcp, void **priv)
{
    HS_CTX_S *pstCtx = *(HS_CTX_S **)priv;

    if (tcp->bypass > 0) {
        return;
    }

    if (pstCtx == NULL) {
        pstCtx = malloc(sizeof(HS_CTX_S));
        if (pstCtx == NULL) {
            return;
        } else {
            HS_InitCtx(pstCtx, g_latest_ts);
        }

        *priv = pstCtx;
    }
    
	switch (tcp->nids_state) {
    	case NIDS_JUST_EST:
    		HS_tcp_create_session(tcp, priv);
    		break;
    	case NIDS_DATA:
    		HS_tcp_process_data(tcp, priv);
    		break;
    	default:
    		HS_tcp_close_session(tcp, priv);
            *priv = NULL;
	}
}

static void HS_udp_create_session(struct udp_stream *udp, void **priv)
{
	udp->server.collect++;
	udp->client.collect++;

	/* there is no handshake in udp stream */
	HS_udp_process_data(udp, priv);
}

static void HS_udp_process_data(struct udp_stream *udp, void **priv)
{
	HS_PKT_DETAIL_S stDetail;
	UINT32  uNeedPrint = 1;
	CHAR buff[64];
	UINT32 appid;
	UINT32 probe_count;
    HS_CTX_S *pstCtx = *(HS_CTX_S **)priv;

    if (pstCtx == NULL) {
        return;
    }

	/* no necessary to detect. */
	if (HS_CTX_SUCCESS(pstCtx)) {
		if (!HS_CTX_MARKED(pstCtx)) {
            udp->bypass = 1;
            *priv = NULL;
            HS_DestroyCtx(pstCtx);
			return;
		} else {
			uNeedPrint = 0;
		}
	}

	stDetail.tuple.protocol = UDP_PROTOCOL;
	stDetail.tuple.addr = udp->addr;
	stDetail.ts = g_latest_ts;

	if (udp->server.count_new) {
		/* client -> server */
		stDetail.direct = DIR_C2S;
		stDetail.data = (UCHAR *)udp->server.data;
		stDetail.length = udp->server.count_new;
	} else if (udp->client.count_new) {
		/* server -> client */
		stDetail.direct = DIR_S2C;
		stDetail.data = (UCHAR *)udp->client.data;
		stDetail.length = udp->client.count_new;
	}

	HS_Probe(pstCtx, &stDetail);

	if (uNeedPrint > 0 && HS_CTX_SUCCESS(pstCtx)) {
		appid = HS_GetAppIdFromCtx(pstCtx);
		probe_count = HS_GetProbeCount(pstCtx);
		HS_FindAppNameByAppId(MASK_VERSION(appid), g_enLang, buff, 64);
		//dump_tuple5(UDP_PROTOCOL, &udp->addr, appid, buff, probe_count);
	}
	
	return;
}
	
static void HS_udp_timeout(struct udp_stream *udp, void **priv)
{
	CHAR buff[64];
	UINT32 appid;
	UINT32 probe_count;
    HS_CTX_S *pstCtx = *(HS_CTX_S **)priv;

    if (pstCtx == NULL) {
        return;
    }

	appid = HS_GetAppIdFromCtx(pstCtx);
	probe_count = HS_GetProbeCount(pstCtx);

	if (!HS_CTX_SUCCESS(pstCtx)) {
		if (HS_IsUnknownId(appid)) {
			if (probe_count < MAX_UDP_EFFECTIVE_PKT_NUM) {
				goto  OUT;
			}
			HS_IncAppCount(g_uAppOther);
            HS_IncAppTrafficCount(g_uAppOther, udp->client.traffic_count + udp->server.traffic_count);
			HS_FindAppNameByAppId(MASK_VERSION(g_uAppOther), g_enLang, buff, 64);
			//dump_tuple5(UDP_PROTOCOL, &udp->addr, appid, buff, probe_count);
		} else {
			assert(HS_CTX_MARKED(pstCtx));
            appid = MASK_VERSION(appid);
            
			HS_IncAppCount(appid);
            HS_IncAppTrafficCount(appid, udp->client.traffic_count + udp->server.traffic_count);
			HS_FindAppNameByAppId(appid, g_enLang, buff, 64);
			//dump_tuple5(UDP_PROTOCOL, &udp->addr, appid, buff, probe_count);
		}
	} else {
		if (HS_CTX_MARKED(pstCtx)) {
			HS_IncAppCount(appid);
		}
        HS_IncAppTrafficCount(appid, udp->client.traffic_count + udp->server.traffic_count);
	}

OUT:
	HS_DestroyCtx(pstCtx);
    free(pstCtx);
}

static void udp_callback(struct udp_stream *udp, void **priv)
{
    HS_CTX_S *pstCtx = *(HS_CTX_S **)priv;

     if (udp->bypass > 0) {
        return;
    }

    if (pstCtx == NULL) {
        pstCtx = malloc(sizeof(HS_CTX_S));
        if (pstCtx == NULL) {
            return;
        } else {
            HS_InitCtx(pstCtx, g_latest_ts);
        }

        *priv = pstCtx;
    }
    
	switch (udp->nids_state) {
    	case NIDS_JUST_EST:
    		HS_udp_create_session(udp, priv);
    		break;
    	case NIDS_DATA:
    		HS_udp_process_data(udp, priv);
    		break;
    	default:
    		HS_udp_timeout(udp, priv);
            *priv = NULL;
	}
}

static INT32 HS_LogInit(void)
{
    INT32 iRet;
    iRet = zlog_init("hslog.conf");
	if (iRet) {
		printf("Zlog init error.\n");
		return HS_ERR;
	}

	g_pstZc = zlog_get_category("hslog");
	if (g_pstZc == NULL) {
		printf("Get log category error.\n");
        zlog_fini();
        return HS_ERR;
	}

    return HS_OK;
}

static void HS_LogExit(void)
{
    zlog_fini();
}

int DPI_Init(void)
{
	INT32 iRet;
    CHAR arrcErrbuf[PCAP_ERRBUF_SIZE];

    iRet = HS_LogInit();
    if (iRet != HS_OK) {
        return -1;
    }
    
	iRet = HS_Load(malloc, free, g_arrcLibFile, "./hs.ini");
	if (iRet != HS_OK) {
        return -1;
	}

	iRet = nids_init();
	if (iRet != 1) {
		HS_FATAL("NIDS init error, Cann't open file?\n");
        return -1;
	}

	nids_register_tcp(tcp_callback);

	nids_register_udp(udp_callback);

    chksum_ctl = malloc(sizeof(struct nids_chksum_ctl));
    if (chksum_ctl == NULL) {
        return 0; // come on baby.
    }
    
	chksum_ctl->netaddr = inet_addr("0.0.0.0");
	chksum_ctl->mask = inet_addr("0.0.0.0");
	chksum_ctl->action = NIDS_DONT_CHKSUM;

	nids_register_chksum_ctl(chksum_ctl, 1);

	return 0;
}

void DPI_Process(const struct pcap_pkthdr *hdr, const unsigned char *data)
{
    nids_pcap_handler(NULL, hdr, data);
}

void DPI_Exit(void)
{
	/* unload appdb */
	HS_Unload();

    HS_LogExit();

    nids_exit();

    if (chksum_ctl != NULL) {
        free(chksum_ctl);
        chksum_ctl = NULL;
    }
}


int DPI_ListAll()
{
    HS_ListAll();
}

int DPI_Version()
{
    HS_version();
}
