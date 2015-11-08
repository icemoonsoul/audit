#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include "dpi.h"

typedef int BOOL;

#ifndef TRUE
#define TRUE    (1==1)
#endif

#ifndef FALSE
#define FALSE   (1==0)
#endif

#define MAX_BUFF_LEN_256    256
#define MAX_BUFF_LEN        64

typedef enum {
    LANG_EN,
    LANG_ZH,
    LANG_MAX
} LANG_TYPE;

BOOL bOffline = FALSE;
char dpi_pcap_file[MAX_BUFF_LEN_256] = {0};
BOOL bLive = FALSE;
char g_arrcSnifferDev[MAX_BUFF_LEN] = {0};
extern LANG_TYPE g_enLang;
pcap_t *pcap_desc;

typedef enum {
    ACTION_UNKNOWN,
    ACTION_SHOW_ALL,
    ACTION_HELP,
    ACTION_VERBOSE,
    ACTION_LIVE,
    ACTION_OFFLINE,
    ACTION_MAX
} ACTION_E;

ACTION_E enCmdAction = ACTION_UNKNOWN;

void usage(void)
{
    printf("Usage: dpi [options] [parameters]\n");
    printf("  -a  show all the applications.\n");
    printf("  -f  offline mode, specify the offline pcap file.\n");
    printf("  -h  this usage guide.\n");
    printf("  -i  live mode, specify the device to sniffer on(eg. eth0/br0).\n");
    printf("  -L  specify language when show applications(eg. en/EN or zh/ZH(utf8)).\n");
    printf("  -v  show verbose information.\n");
}

int parse_cmd(int argc, char *const *argv)
{
    char ch;
    int iRet;

    if (argc < 2) {
        usage();
        exit(1);
    }

    while ((ch = getopt(argc, argv, "hvai:f:L:")) != -1) {
        switch (ch) {
            case 'a':
                enCmdAction = ACTION_SHOW_ALL;
                break;
            case 'f':
                strncpy(dpi_pcap_file, optarg, MAX_BUFF_LEN_256 - 1); 
                dpi_pcap_file[MAX_BUFF_LEN_256 - 1] = '\0';
                bOffline = TRUE;
                enCmdAction = ACTION_OFFLINE;
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
            case 'L':
                if (strncmp(optarg, "en", strlen("en")) == 0 || strncmp(optarg, "EN", strlen("en")) == 0) {
                    g_enLang = LANG_EN;
                } else if (strncmp(optarg, "zh", strlen("en")) == 0 || strncmp(optarg, "ZH", strlen("en")) == 0) {
                    g_enLang = LANG_ZH;
                } else {
                    printf("Unknown language.\n");
                    usage();
                    exit(-1);
                }

                break;
            case 'v':
                enCmdAction = ACTION_VERBOSE;
                break;
            default:
                printf("Parse command line parameter error.\n");
                usage();
                goto ERROR;
        }
    }

    switch (enCmdAction) {
        case ACTION_SHOW_ALL:
            DPI_Init();
            DPI_ListAll();
            DPI_Exit();
            break;
        case ACTION_HELP:
            usage();
            break;
        case ACTION_VERBOSE:
            DPI_Init();
            DPI_Version();
            DPI_Exit();
            break;
        case ACTION_LIVE:
        case ACTION_OFFLINE:
            return 0;
        default:
            usage();
            exit(-1);
    }

    exit(0);
ERROR:
    return -1;
}

void dpi_handler(u_char * par, const struct pcap_pkthdr *hdr, const u_char *data)
{
    DPI_Process(hdr, data);
}

int main1(int argc, char **argv)
{
    int iRet;
    char nids_errbuf[PCAP_ERRBUF_SIZE];

    iRet = parse_cmd(argc, argv);
    if (iRet != 0) {
        exit(-1);       
    }

    if (bLive && bOffline) {
        printf("Live mode and Offline mode can't work together.\n");
        usage();
        exit(-1);
    }

    if (!bLive && !bOffline) {
        printf("Please specify one work mode between live(-i) and offline(-f).\n");
        usage();
        exit(-1);
    }

    if (bLive) {
        pcap_desc = pcap_open_live(g_arrcSnifferDev, 65535, 1, 0, nids_errbuf);
        if (pcap_desc == NULL) {
            printf("Open device: %s error.\n", g_arrcSnifferDev);
            exit(-1);
        }
    } else if (bOffline) {
        /* specify the pcap file */
        if (!dpi_pcap_file[0]) {
            printf("No pcap file was specified.\n");
            usage();
            exit(-1);
        }

        pcap_desc = pcap_open_offline(dpi_pcap_file, nids_errbuf);
        if (pcap_desc == NULL) {
            printf("Open file: %s error.\n", dpi_pcap_file);
            exit(-1);
        }
    } 

    if (DPI_Init() != 0) {
        printf("DPI_Init error.\n");
        exit(-1);
    }

    pcap_loop(pcap_desc, -1, dpi_handler, 0);

    DPI_Exit();

    return 0;
}

#include "hs.smtp.h"

extern void Mime_HeadInfo_Extracted(MIME_HEAD_INFO_S *pstMime_head_info, FILE *fp);

int main(void)
{
	MIME_HEAD_INFO_S info;
	FILE *fp;
	char test1[1024] = "=?gb2312?B?u9i4tDogMjIzMzMzMzMzMzMzMzMzMzMzMzM=?=";
	char test2[1024] = "sec2302 <sec2302@opzoon23.com>, \r\n.sec2301 <sec2301@opzoon23.com>";
	char test3[1024] = "=?gb2312?B?t6K078nPsLTKsbXYt73I9rWpt6iwtMqxtdi3vbCutc/J+reiyeS147eiyfq3osnkteOwtMqxtcS3\r\nosnkteO3qLC0yrG1xLeiyfqwtMqxsKG3qLC4yc8NCreit6LJ+reiyfqwtMqxtcS3osn6sLTKsbXE?=";

	info.arrInfo[0].pucData = test1;
	info.arrInfo[0].uLen = strlen(test1);
	info.arrInfo[1].pucData = test1;
	info.arrInfo[1].uLen = strlen(test2);
	info.arrInfo[2].pucData = test1;
	info.arrInfo[2].uLen = strlen(test2);

	fp = fopen("1.log", "a+");
    if (fp == NULL)
    {
            return HOOK_ACTION_CONTINUE;
    }
    fseek(fp, 0L, 2);

	Mime_HeadInfo_Extracted(&info, fp);
	
	fclose(fp);
	
	
}
