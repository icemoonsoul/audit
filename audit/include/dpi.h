#ifndef _DPI_H_
#define _DPI_H_

int DPI_Init(void);
void DPI_Process(const struct pcap_pkthdr *hdr, const unsigned char *data);
void DPI_Exit(void);
int DPI_ListAll();
int DPI_Version();

#endif
