#include <string.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <util.h>
#include <signal.h>
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
BOOL bOffline = FALSE;
CHAR HS_pcap_file[MAX_BUFF_LEN_256] = {0};
BOOL bLive = FALSE;
CHAR g_arrcSnifferDev[MAX_BUFF_LEN] = {0};
zlog_category_t *g_pstZc = NULL;
CHAR g_arrcGroup[MAX_BUFF_LEN] = {0};
CHAR g_arrcInner[MAX_BUFF_LEN] = {0};

typedef enum {
    ACTION_UNKNOWN,
    ACTION_SHOW_ALL,
    ACTION_SHOW_GROUP,
    ACTION_HELP,
    ACTION_VERBOSE,
    ACTION_LIVE,
    ACTION_OFFLINE,
    ACTION_MAX
} ACTION_E;

ACTION_E enCmdAction = ACTION_UNKNOWN;

void HS_udp_process_data(struct udp_stream *udp, void **priv);

void dump_tuple5(int protocol, struct tuple4 *addr, UINT32 app_id, const CHAR *app_name, UINT32 probe_count);

void show_summary()
{
	HS_PRINT("Summary:\n");
	HS_PRINT("application                              session number                      traffic count\n");

	HS_ShowAppStat();
}

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
	//	(addr->source), (addr->dest), app_name, proc_count);

#ifdef HS_PRINTT_STAT
	HS_PRINT("%8s%18s%18s%14d%14d    %23s\n\n", protocol_str, saddr_str, daddr_str, \
		(addr->source), (addr->dest), app_name);
#endif    
    return;
}

void HS_tcp_create_session(struct tcp_stream *tcp, void **priv)
{
    HS_CTX_S *pstCtx;
    
    pstCtx = malloc(sizeof(HS_CTX_S));
    if (pstCtx == NULL) {
        return;
    } else {
        HS_InitCtx(pstCtx, g_latest_ts);
    }

    *priv = pstCtx;

    tcp->server.collect++;
	tcp->client.collect++;
    
	return;
}

void HS_tcp_process_data(struct tcp_stream *tcp, void **priv)
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
	} else {
        return;
    }

	HS_Probe(pstCtx, &stDetail);

	if (uNeedPrint > 0 && HS_CTX_SUCCESS(pstCtx)) {
		appid = HS_GetAppIdFromCtx(pstCtx);
		probe_count = HS_GetProbeCount(pstCtx);
		HS_FindAppNameByAppId(MASK_VERSION(appid), g_enLang, buff, 64);
		dump_tuple5(TCP_PROTOCOL, &tcp->addr, appid, buff, probe_count);
	}

	if (HS_CTX_SUCCESS(pstCtx) && !HS_CTX_MARKED(pstCtx)) {
        tcp->bypass = 1;
        *priv = NULL;
        HS_DestroyCtx(pstCtx);
        free(pstCtx);
	}

}

void HS_tcp_close_session(struct tcp_stream *tcp, void **priv)
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

void tcp_callback(struct tcp_stream *tcp, void **priv)
{
    if (tcp->bypass > 0) {
        return;
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
    HS_CTX_S *pstCtx;
    
    pstCtx = malloc(sizeof(HS_CTX_S));
    if (pstCtx == NULL) {
        return;
    } else {
        HS_InitCtx(pstCtx, g_latest_ts);
    }

    *priv = pstCtx;

    udp->server.collect++;
	udp->client.collect++;

	/* there is no handshake in udp stream */
	HS_udp_process_data(udp, priv);
}

void HS_udp_process_data(struct udp_stream *udp, void **priv)
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
	} else {
        return;
    }

	HS_Probe(pstCtx, &stDetail);

	if (uNeedPrint > 0 && HS_CTX_SUCCESS(pstCtx)) {
		appid = HS_GetAppIdFromCtx(pstCtx);
		probe_count = HS_GetProbeCount(pstCtx);
		HS_FindAppNameByAppId(MASK_VERSION(appid), g_enLang, buff, 64);
		//dump_tuple5(UDP_PROTOCOL, &udp->addr, appid, buff, probe_count);
	}

    if (HS_CTX_SUCCESS(pstCtx) && !HS_CTX_MARKED(pstCtx)) {
        udp->bypass = 1;
        *priv = NULL;
        HS_DestroyCtx(pstCtx);
        free(pstCtx);
	}
	
	return;
}
	
void HS_udp_timeout(struct udp_stream *udp, void **priv)
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

void udp_callback(struct udp_stream *udp, void **priv)
{
    if (udp->bypass > 0) {
        return;
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

void usage(void)
{
	HS_PRINT("Usage: hyperscan [options] [parameters]\n");
    HS_PRINT("  -a	show all the applications.\n");
    HS_PRINT("  -f	offline mode, specify the offline pcap file.\n");
    HS_PRINT("  -g	show the applications in the certain group.\n");
	HS_PRINT("  -h	this usage guide.\n");
    HS_PRINT("  -i	live mode, specify the device to sniffer on(eg. eth0/br0).\n");
    HS_PRINT("  -s	specify inner ip address like 10.0.0.1/10.0.0.2/10.0.0.3.\n");
    HS_PRINT("  -l	specify library file, \"dpi.lib\" as default.\n");
    HS_PRINT("  -L	specify language when show applications(eg. en/EN or zh/ZH(utf8)).\n");
	HS_PRINT("  -v	show verbose information.\n");
}

INT32 parse_cmd(INT32 argc, CHAR * const *argv)
{
	CHAR ch;
    INT32 iRet;

	if (argc < 2) {
		usage();
		exit(1);
	}

	while ((ch = getopt(argc, argv, "hvf:ag:s:l:i:L:")) != -1) {
		switch (ch) {
    		case 'a':
                enCmdAction = ACTION_SHOW_ALL;
    			break;
            case 'f':
    			strncpy(HS_pcap_file, optarg, MAX_BUFF_LEN_256 - 1); 
                HS_pcap_file[MAX_BUFF_LEN_256 - 1] = '\0';
                bOffline = TRUE;
                enCmdAction = ACTION_OFFLINE;
    			break;
    		case 'g':
                enCmdAction = ACTION_SHOW_GROUP;
                strncpy(g_arrcGroup, optarg, MAX_BUFF_LEN - 1);
                g_arrcGroup[MAX_BUFF_LEN - 1] = '\0';
    			break;
    		case 'h':
                enCmdAction = ACTION_HELP;
    			break;
            case 'i':
    			strncpy(g_arrcSnifferDev, optarg, MAX_BUFF_LEN - 1);
                g_arrcSnifferDev[MAX_BUFF_LEN - 1] = '\0';
                bLive = TRUE;
                enCmdAction = ACTION_LIVE;
    			break;
            case 'l':
                strncpy(g_arrcLibFile, optarg, MAX_BUFF_LEN - 1);
                g_arrcLibFile[MAX_BUFF_LEN - 1] = '\0';
    			break;
            case 'L':
                if (strncmp(optarg, "en", strlen("en")) == 0 || strncmp(optarg, "EN", strlen("en")) == 0) {
                    g_enLang = LANG_EN;
                } else if (strncmp(optarg, "zh", strlen("en")) == 0 || strncmp(optarg, "ZH", strlen("en")) == 0) {
                    g_enLang = LANG_ZH;
                } else {
                    HS_FATAL("Unknown language.\n");
                    usage();
                    exit(-1);
                }

    			break;
    		case 's':
                strcpy(g_arrcInner, optarg);
    			break;
    		case 'v':
                enCmdAction = ACTION_VERBOSE;
    			break;
    		default:
    			HS_FATAL("Parse command line parameter error.\n");
    			usage();
    			goto ERROR;
		}
	}

    switch (enCmdAction) {
        case ACTION_SHOW_ALL:
            iRet = HS_Load(malloc, free, g_arrcLibFile, "./hs.ini");
            if (iRet != HS_OK) {
	            exit(-1);
            }
			HS_ListAll();
            break;
        case ACTION_SHOW_GROUP:
            iRet = HS_Load(malloc, free, g_arrcLibFile, "./hs.ini");
            if (iRet != HS_OK) {
	            exit(-1);
            }
			HS_ListGroup(g_arrcGroup);
            break;
        case ACTION_HELP:
    		usage();
            break;
        case ACTION_VERBOSE:
            iRet = HS_Load(malloc, free, g_arrcLibFile, "./hs.ini");
            if (iRet != HS_OK) {
	            exit(-1);
            }
			HS_version();
            break;
        case ACTION_LIVE:
        case ACTION_OFFLINE:
            return HS_OK;
        default:
            usage();
            exit(-1);
    }

    exit(0);
ERROR:
	return HS_ERR;
}

INT32 HS_LogInit(void)
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

void HS_LogExit(void)
{
    zlog_fini();
}

void ProcessSIGINT(int signo)
{
    //show_summary();

    exit(0);
}

INT32 main(INT32 argc, CHAR * const *argv)
{
	INT32 iRet;
	struct nids_chksum_ctl *chksum_ctl;
    CHAR arrcErrbuf[PCAP_ERRBUF_SIZE];

    iRet = HS_LogInit();
    if (iRet != HS_OK) {
        exit(-1);
    }

    HS_INFO("***************************************************************************\n");
    HS_INFO("*                             Hello, HyperScan!                           *\n");
    HS_INFO("***************************************************************************\n");
    if (argc >= 2 && strcmp(argv[1], "-h") == 0) {
        usage();
        exit(0);
    }

    iRet = parse_cmd(argc, argv);
	if (iRet != HS_OK) {
		exit(-1);		
	}
    
	iRet = HS_Load(malloc, free, g_arrcLibFile, "./hs.ini");
	if (iRet != HS_OK) {
		exit(-1);
	}

    if (strlen(g_arrcInner) != 0) {
        HS_AddInnerIp(g_arrcInner);
    }

    if (bLive && bOffline) {
        HS_FATAL("Live mode and Offline mode can't work together.\n");
        usage();
        exit(-1);
    }

    if (!bLive && !bOffline) {
        HS_FATAL("Please specify one work mode between live(-i) and offline(-f).\n");
        usage();
        exit(-1);
    }

    if (bLive) {
        nids_params.pcap_desc = pcap_open_live(g_arrcSnifferDev, 65535, 1, 0, arrcErrbuf);
        if (nids_params.pcap_desc == NULL) {
            HS_FATAL("Open device: %s error.\n", g_arrcSnifferDev);
            HS_FATAL("Error info: %s\n", arrcErrbuf);
            exit(-1);
        }
    } else if (bOffline) {
    	/* specify the pcap file */
    	if (!HS_pcap_file[0]) {
    		HS_FATAL("No pcap file was specified.\n");
    		usage();
    		exit(-1);
    	}

        nids_params.filename = HS_pcap_file;
    } 
    
	/* nids initialize */
	iRet = nids_init(1);
	if (iRet != 1) {
		HS_FATAL("NIDS init error, Cann't open file?\n");
		exit(-1);
	}

	nids_register_tcp(tcp_callback);

	nids_register_udp(udp_callback);

	chksum_ctl = malloc(sizeof(struct nids_chksum_ctl));
	chksum_ctl->netaddr = inet_addr("0.0.0.0");
	chksum_ctl->mask = inet_addr("0.0.0.0");
	chksum_ctl->action = NIDS_DONT_CHKSUM;

	nids_register_chksum_ctl(chksum_ctl, 1);

#ifdef HS_PRINTT_STAT
    HS_PRINT("Session List:\n");
#endif

#ifndef PRINT_DFI
#ifdef HS_PRINTT_STAT	
	HS_PRINT("l4_proto          src_addr          dst_addr      src_port       dst_port                application\n");
#endif
#else
	HS_PRINT("protocol  src_addr  dst_addr  src_port  dst_port  app_id  app_name proc_count s2c_len c2s_len radio s2c_total c2s_total\n");
#endif

    if (signal(SIGINT, ProcessSIGINT) == SIG_ERR) {
        HS_PRINT("signal SIGINT error.\n"); 
        exit(-1);
    }

	/* read pcap data and process them */
	nids_run();

#ifdef HS_PRINTT_STAT	
	show_summary();
#endif

	/* unload appdb */
	HS_Unload();

    HS_LogExit();

	free(chksum_ctl);
    
	return 0;
}
