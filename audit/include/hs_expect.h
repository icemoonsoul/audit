#ifndef __HS_EXPECT_H_
#define __HS_EXPECT_H_

#define HS_EXPECT_HASH_CAPTY                           5000
#define HS_EXPECT_LIST_TIMEOUT                         600000
#define HS_EXPECT_SCAN_NUM_EVERY_CONN                  1
#define HS_EXPECT_IPLIST_NUM_LIMIT                     1000

#define HS_EXPECT_FREE_NODE(pnode) \
    if (pnode != NULL) \
    { \
        hs_free(pnode); \
        pnode = NULL; \
    }

#define HS_EXPECT_ADD_LIST(pnode, phead, count) \
    list_add_tail(pnode, phead); \
    atomic_inc(count);

#define HS_EXPECT_ADD_IPLIST(pnode, phead, count) \
    HS_EXPECT_ADD_LIST(pnode, phead, count)

#define HS_EXPECT_ADD_TSLIST(pnode, phead, count) \
    HS_EXPECT_ADD_LIST(pnode, phead, count)

#define HS_EXPECT_DEL_TSLIST(pnode, count) \
    list_del(pnode); \
    atomic_dec(count);

#define HS_EXPECT_DEL_IPLIST(phash, pold_ipnode, pold_info, ptold_ipnode, index) \
    list_del(&(pold_info)->ip_list); \
    HS_EXPECT_FREE_NODE((pold_info)) \
    atomic_dec(&(pold_ipnode)->info_count); \
    if (0 == atomic_read(&(pold_ipnode)->info_count)) \
    { \
        ptold_ipnode = HS_HASH_ReleaseWithoutLock(phash, pold_ipnode, index); \
        HS_EXPECT_FREE_NODE(ptold_ipnode) \
    }

#define HS_EXPECT_IPLIST_NODE_IS_LIMIT(count) \
    ((count) > HS_EXPECT_IPLIST_NUM_LIMIT)

typedef enum {
    EXPECT_ACTION_INVALID = 0,
    EXPECT_ACTION_UPDATE,
    EXPECT_ACTION_DELETE,
    EXPECT_ACTION_MAX
} EXPECT_ACTION_E;

typedef enum {
    HS_EXPECT_MATCHED_FLAG_INVALID = 0,
    HS_EXPECT_MATCHED_FLAG_YES,
    HS_EXPECT_MATCHED_FLAG_NO,
    HS_EXPECT_MATCHED_FLAG_MAX
} EXPECT_MATCHED_FLAG_E;

typedef struct 
{
    UINT8 opt_flag;
    UINT8 match_flag;
    struct list_head ts_list;
    struct list_head ip_list;
    struct tuple5 tuple;
    struct tuple5 mask;
    UINT32 appid;
    HS_time_t creat_ts;
    HS_time_t dest_ts;
    void *prv;
} EXPECT_INFO_S;

typedef struct {
    struct list_head iplist_head;
    UINT32 saddr;
    atomic_t info_count;
} EXPECT_IP_NODE_S;

typedef struct
{
    struct list_head tslist_head;
    struct hash *expect_hash;
    HS_rwlock_t tslist_lock;
    atomic_t	tslist_count;
} EXPECT_DATA_S;

INT32 HS_EXPECT_HashInsert(const EXPECT_INFO_S *pstInfo);

void dump_expect_info(const EXPECT_INFO_S *info);

INT32 HS_EXPECT_Init(void);

#endif
