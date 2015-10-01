#ifndef _HS_DNS_H_
#define _HS_DNS_H_

#include "hs_expect.h"

/**************************************************************************
 * dns plugin
 *************************************************************************/
#define HS_DNS_NAME 			"dns"
#define DNS_MAX_ANSWER 			20
#define DNS_ENABLE     			0
#define DNS_DISABLE    			1
#define DNS_REQUEST     		0
#define DNS_RESPONSE    		1
#define DNS_HASH_SIZE       	1024
#define DNS_NAME_MAX_LEN 		128      //the maxsize of domain name 

#define IS_DNS_RESPONSE(flag)   ((flag) & 0x80)
#define IS_ASSOCIATED(ctx)       ((ctx)->priv_data != NULL)
#define IS_NON_ASSOCIATED(ctx)   ((ctx)->priv_data == NULL)

#define IS_COMPRESS_FORMAT(len) (((len) & 0x80) && ((len) & 0x40))
#define IS_NORMAL_FORMAT(len)   (!((len) & 0xC0))

enum domain_type{
    DOMAIN_TYPE_INVALID,
    NON_ASSOCIATED,
    ASSOCIATED,
    DOMAIN_TYPE_MAX
};

typedef struct dns_head {
    UINT16 qid;
    UINT16 flag;
    UINT16 qdcount;
    UINT16 ancount;
    UINT16 nscount;
    UINT16 arcount;
} dns_head_t; 

typedef struct dns_packet {
    dns_head_t head;
    UINT8 data[0];
} dns_packet_t;

typedef struct dns_domain {
    UINT32 ip_num;
    UINT32 ip_size;
    UINT16 type;
    UINT16 clas;
    UINT32 time;
    UINT8 name[DNS_NAME_MAX_LEN];
    UINT32 *ip_array;
} dns_domain_t;

   
typedef struct dns_domain_map {
    struct list_head list;
    struct tuple5 mask;
    UINT32   protocol;
    UINT32   appid;
    HS_time_t  ts;
    enum domain_type type;
    EXPECT_ACTION_E opt_flag;
    CHAR name[DNS_NAME_MAX_LEN];
} dns_domain_map_t;

struct dns_global {
    atomic_t	map_num;
    atomic_t    t_list_num;
    UINT32		enable;
    UINT32		appid;
    struct		list_head timeout_list;
    struct		hash *hash;
    HS_rwlock_t timeout_lock;
};

typedef struct dns_pkt_option {
    INT32     	alias;
    UINT32     	ancount;
    const UINT8 *dns_begin;
    const UINT8 *dns_end;
    const UINT8 *anpos;
} dns_pkt_option_t;

typedef struct HS_dns {
    UINT16 dns_count;  
    EXPECT_ACTION_E opt_flag;
    UINT32 appid;           
    UINT32 protocol;   
    struct tuple5 mask;
} HS_dns_t;

INT32 HS_DNS_Insert(dns_domain_map_t *node);

INT32 HS_DNS_Init(void);

#endif
