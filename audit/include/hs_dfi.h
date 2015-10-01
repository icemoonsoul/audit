#ifndef _HS_DFI_H_
#define _HS_DFI_H_

/**************************************************************************
 * dfi plugin
 *************************************************************************/
/*
	Part of DPI Behavior Module, stat the information of the packets and connections, which
	include packet number, packet length, packet frequency, connection number, connection 
	frequency, connection number, the top level of these information is about host. There is
	no relationship between hosts.

	Behavior Match Module will be otherwhere, which will be responsibility for matching 
	behavior signature.

	The stat and match module will be separate, so lock protecting is needful in multi-thread
	environment.
*/

#define INIT_HOST_NUM 1024
#define INIT_CONN_NUM 128
#define HS_DFI_START_STAT_NUM 8
#define HS_DFI_STAT_PACKET_NUM 16
#define HS_DFI_SAMPLE_RATIO 8
#define HS_STAT_COUNT (HS_DFI_START_STAT_NUM + HS_DFI_STAT_PACKET_NUM)
#define HS_DFI_START_SCAN_NUM HS_STAT_COUNT 

typedef struct {
	UINT16 protocol;							        // level4 protocol, tcp or udp
	UINT16 port;								        // tcp or udp port

	UINT16 pkt_len_c2s[HS_DFI_STAT_PACKET_NUM];		// packet list of this connection
	UINT16 pkt_len_s2c[HS_DFI_STAT_PACKET_NUM];		// packet list of this connection

	UINT16 pkt_len_av_c2s;					            // average of c2s pakcet length
	UINT16 pkt_len_av_s2c;					            // average of s2c pakcet length

	UINT16 pkt_len_ratio;								//nearlest 20 s2c packet total len / c2s packet total len
} DFI_CONN_STAT_S;

/* Warning: the array of the elements in this structure cann't be reordered. */
typedef struct dfi_conn {
	DFI_CONN_STAT_S stConnStat;	

	UINT16 pkt_num_c2s;
	UINT16 pkt_num_s2c;
#if 0
	UINT16 pkt_num_all;				// the number of the packets of this connection
#endif

#if 0
	UINT16 pkt_load_c2s;			// total of c2s pakcet length
	UINT16 pkt_load_s2c;			// total of s2c pakcet length
#endif
	UINT16 usPktLenTotalC2S;		//total of c2s packet length before 20
	UINT16 usPktLenTotalS2C;		//total of s2c packet length before 20
#if 0
	UINT16 arrRadioPktLenC2S[DFI_RADIO_PKT_SAVE_NUM];
	UINT16 arrRadioPktLenS2C[DFI_RADIO_PKT_SAVE_NUM];
#endif
	UINT16 usRadioPktLenTotalC2S;
	UINT16 usRadioPktLenTotalS2C;
#if 0
	struct tuple4 tuple;			// tuple

	HS_time_t create_ts;			// creating time
	HS_time_t current_ts;
#endif
} DFI_CONN_S;

static inline void DFI_Enable(HS_DATA_S *pstDpi)
{
	pstDpi->bDfiEnable = TRUE;	
}

static inline void DFI_Disable(HS_DATA_S *pstDpi)
{
	pstDpi->bDfiEnable = FALSE;
}

void HS_DFI_ConnDestroy(struct dfi_conn *conn);

INT32 HS_DFI_Init(HS_DATA_S *pstHs);

#endif
