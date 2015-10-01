#ifndef _HS_STAT_H_
#define _HS_STAT_H_

#include "hs_core.h"

extern u32 g_uStat;
extern atomic_t g_atPluginDealStat[HS_PLUGIN_MAX];
extern atomic_t g_atPluginIdentifyStat[HS_PLUGIN_MAX];

#define HS_PLUGIN_DEAL_STAT(plugin) \
    do { \
        if (g_uStat > 0 && plugin > 0 && plugin < HS_PLUGIN_MAX) { \
            g_atPluginDealStat[plugin]++; \
        } \
    } while (0)

#define HS_PLUGIN_IDENTIFY_STAT(plugin) \
    do { \
        if (g_uStat > 0 && plugin > 0 && plugin < HS_PLUGIN_MAX) { \
            g_atPluginIdentifyStat[plugin]++; \
        } \
    } while (0)

void HS_Stat_Init(void);

#endif
