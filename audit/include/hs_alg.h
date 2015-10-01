#ifndef __HS_BI_H_
#define __HS_BI_H_

#if MODE == USERSPACE
#include <string.h>
#include "hs_list.h"
#elif MODE == KERNELSPACE
#include <linux/list.h>
#endif

#include "hs.h"

extern MALLOC_FUNC 	hs_malloc;
extern FREE_FUNC	hs_free;

#define HS_TIME_SEC(ts)		        ((ts).tv_sec)
#define HS_TIME_MSEC(ts)		        ((ts).tv_usec/1000)
#define HS_TIME_ADD_MSEC(ts, delta)    ((ts).tv_usec += (delta)* 1000)

typedef struct _tree_node {
	struct _tree_node *pstLeft;
	struct _tree_node *pstRight;
	void *pData;
} TREE_NODE_S;

typedef void (*STACK_HOOK)(void *pData);

typedef struct _stack_node{
	LIST_HEAD_S stList;
	void *pData;	
} STACK_NODE_S;

typedef struct _stack {
	atomic_t atCount;		
	LIST_HEAD_S stHead;
} STACK_S;

typedef UINT32 IPADDR_T;

static inline INT32 strempty(const CHAR *str)
{
	if ( str && *str) {
		return 0;
	} else {
		return 1;
    }
}

static inline INT32 HS_isdigit(INT32 c)
{
  return (((c) >= '0') && ((c) <= '9'));
}

static inline UINT16 HS_Reverse16(UINT16 usInit)
{
	return (UINT16)((usInit&0xff) << 8 | (usInit&0xff00) >> 8);
}

static inline UINT32 HS_Reverse32(UINT32 uInit)
{
	return (uInit & 0xff) << 24 | (uInit & 0xff00) << 8 |(uInit & 0xff0000) >> 8 | (uInit & 0xff000000) >> 24 ;
}

/* network sequence as default */
int HS_IpNtoa(INT32 nSeq, IPADDR_T uIpAddr, CHAR *pBuff, UINT32 uLen);

IPADDR_T HS_IpAton(INT32 nSeq, const CHAR *pBuff);

static inline INT32 TS_DELTA_MS(HS_time_t *ts1, HS_time_t *ts2)
{
	return (INT32)((HS_TIME_SEC(*ts2) - HS_TIME_SEC(*ts1)) * 1000 
		+ HS_TIME_MSEC(*ts2) - HS_TIME_MSEC(*ts1)); 
}
 
static inline INT32 TS_DELTA_SEC(HS_time_t *ts1, HS_time_t *ts2)
{
	return (INT32)(HS_TIME_SEC(*ts2) - HS_TIME_SEC(*ts1));
}

static inline INT32 ts_bigger(HS_time_t *ts1, HS_time_t *ts2)
{
	return (INT32)(HS_TIME_SEC(*ts1) == HS_TIME_SEC(*ts2) ? HS_TIME_MSEC(*ts1) - HS_TIME_MSEC(*ts2):\
		HS_TIME_SEC(*ts1) - HS_TIME_SEC(*ts2));
}

/*
	check whether the delta in milliseconds between ts2 and ts1 is larger than max_delta_tv,
	return HS_ERR if yes and return HS_OK if no.
*/
static inline INT32 HS_VERIFY_TS(HS_time_t *ts1, HS_time_t *ts2, INT32 max_delta_tv)
{
	INT32 delta = TS_DELTA_MS(ts1, ts2);
	
	if(delta > max_delta_tv) {
		return HS_ERR;
	}

	return HS_OK;
}
 
static inline void HS_SET_TS(HS_time_t *ts1, HS_time_t *ts2, INT32 timeout)
{
	INT32 tmp;

	HS_TIME_SEC(*ts1) = HS_TIME_SEC(*ts2) + timeout/1000;

    tmp =( HS_TIME_MSEC(*ts1) + HS_TIME_MSEC(*ts2) + timeout%1000);
	if (tmp < 1000) {
		HS_TIME_ADD_MSEC(*ts1, HS_TIME_MSEC(*ts2) + timeout%1000);
	} else {
		HS_TIME_SEC(*ts1) += 1;
		HS_TIME_ADD_MSEC(*ts1, HS_TIME_MSEC(*ts2) + timeout%1000 - 1000);
	}
}

UCHAR *HS_DataChar(UCHAR *pucData, UINT32 uLen, UCHAR ucChar);


typedef int (*WALK)(void *pData, void *pPriv);

static inline TREE_NODE_S *TREE_NewNode(void *pData)
{
	TREE_NODE_S *pstNode = hs_malloc(sizeof(TREE_NODE_S));		
	if(NULL == pstNode) {
		return NULL;
	}
	memset(pstNode, 0, sizeof(TREE_NODE_S));
	pstNode->pData = pData;
	return pstNode;
}

static inline void TREE_DestroyNode(TREE_NODE_S *pstNode)
{
	hs_free(pstNode);

	return;
}

static inline int TREE_AddLeft(TREE_NODE_S *pFather, TREE_NODE_S *pstLeft)
{
	if(NULL == pFather || NULL == pstLeft)	
		return HS_ERR;
	if(NULL != pFather->pstLeft)
		return HS_ERR;

	pFather->pstLeft = pstLeft;

	return HS_OK;
}

static inline int TREE_AddRight(TREE_NODE_S *pFather, TREE_NODE_S *pstRight)
{
	if(NULL == pFather || NULL == pstRight)	
		return HS_ERR;
	if(NULL != pFather->pstRight)
		return HS_ERR;

	pFather->pstRight = pstRight;

	return HS_OK;
}

static inline TREE_NODE_S *TREE_DeleteLeft(TREE_NODE_S *pFather)
{
	TREE_NODE_S *pTmp;
	if(NULL == pFather || NULL == pFather->pstLeft) {	
		return NULL;
	}

	pTmp = pFather->pstLeft;
	pFather->pstLeft = NULL;

	return pTmp;
}

static inline TREE_NODE_S *TREE_DeleteRight(TREE_NODE_S *pFather)
{
	TREE_NODE_S *pTmp;
	if(NULL == pFather || NULL == pFather->pstRight)	
		return NULL;

	pTmp = pFather->pstRight;
	pFather->pstRight = NULL;

	return pTmp;
}

typedef void (*PFUNC_TREE_HOOK)(TREE_NODE_S *pstNode, void *pPriv);

static inline void TREE_WalkPreOrder(PFUNC_TREE_HOOK pfunc, TREE_NODE_S *pFather, void *pPriv)
{
	if(pFather) {
		pfunc(pFather, pPriv);
	}

	if(pFather && pFather->pstLeft) {
		TREE_WalkPreOrder(pfunc, pFather->pstLeft, pPriv);
	}

	if(pFather && pFather->pstRight) {
		TREE_WalkPreOrder(pfunc, pFather->pstRight, pPriv);	
	}
}


static inline void TREE_WalkInOrder(PFUNC_TREE_HOOK pfunc, TREE_NODE_S *pFather, void *pPriv)
{
	if(pFather && pFather->pstLeft) {
		TREE_WalkInOrder(pfunc, pFather->pstLeft, pPriv);
	}

	if(pFather) {
		pfunc(pFather, pPriv);
	}

	if(pFather && pFather->pstRight) {
		TREE_WalkInOrder(pfunc, pFather->pstRight, pPriv);	
	}
}

static inline void TREE_WalkPostOrder(PFUNC_TREE_HOOK pfunc, TREE_NODE_S *pFather, void *pPriv)
{
	if(pFather && pFather->pstLeft) {
		TREE_WalkPostOrder(pfunc, pFather->pstLeft, pPriv);
	}

	if(pFather && pFather->pstRight) {
		TREE_WalkPostOrder(pfunc, pFather->pstRight, pPriv);	
	}

	if(pFather) {
		pfunc(pFather, pPriv);
	}
}

static inline int STACK_Empty(STACK_S *pStack)
{
	if(NULL == pStack)
		return HS_ERR;

	if(atomic_read(&pStack->atCount) == 0)
		return HS_OK;

	return HS_ERR;
}

static inline void INIT_STACK(STACK_S *pstStack)
{
	if(NULL == pstStack) {
		return;	
	}
	
	INIT_LIST_HEAD(&pstStack->stHead);
	atomic_set(&pstStack->atCount, 0);

	return;
}

static inline STACK_S *STACK_New(void)
{
	STACK_S *pstStack;

    pstStack = hs_malloc(sizeof(STACK_S));	
	if (NULL == pstStack) {
		return NULL;
	}

	INIT_STACK(pstStack);

	return pstStack;
}

static inline STACK_NODE_S *STACK_New_Node(void)
{
	STACK_NODE_S *pNode;

    pNode = hs_malloc(sizeof(STACK_NODE_S));	
	if (NULL == pNode) {
		return NULL;
	}

	INIT_LIST_HEAD(&pNode->stList);
	pNode->pData = NULL;

	return pNode;
}

static inline void STACK_FreeNode(STACK_NODE_S *pNode, STACK_HOOK pfuncHook)
{
	if (NULL == pNode) {
		return; 
	}

	pfuncHook(pNode->pData);
	hs_free(pNode);	

	return;
}

static inline int STACK_Push(STACK_S *pstStack, STACK_NODE_S *pstStackNode)
{
	if(NULL == pstStack || NULL == pstStackNode) {
		return HS_ERR;
	}

	list_add(&pstStackNode->stList, &pstStack->stHead);
	atomic_inc(&pstStack->atCount);

	return HS_OK;
}

static inline STACK_NODE_S *STACK_Pop(STACK_S *pstStack)
{
    STACK_NODE_S *pNode;
    
    if(NULL == pstStack || atomic_read(&pstStack->atCount) == 0) {
		return NULL;	
	}

	pNode = list_first_entry(&pstStack->stHead, STACK_NODE_S, stList);
	if(NULL == pNode) {
		return NULL;	
	}

	list_del(&pNode->stList);

	atomic_dec(&pstStack->atCount);

	return pNode;
}


static inline int STACK_Destroy(STACK_S *pStack, STACK_HOOK pfuncHook)
{
	STACK_NODE_S *pNode;		

	while(STACK_Empty(pStack) != HS_OK) {
		pNode = STACK_Pop(pStack);	
		(*pfuncHook)(pNode->pData);
	}	

	return HS_OK;
}

/******************************************************************************
*   hash table 
******************************************************************************/
/* Default hash table size.  */ 
#define HASHTABSIZE     		128
#define HS_HASH_INDEX_INVALID	0xffffffff

enum HS_HASH_ACTION_TYPE {
	HS_HASH_CONTINUE,
	HS_HASH_BREAK,
	HS_HASH_DELETE_CONTINUE,
	HS_HASH_DELETE_BREAK,
	HS_HASH_MAX
};

struct hash_backet
{
	/* Linked list.  */
	struct hash_backet *next;
	/* Data.  */
	void *data;
};

struct hash
{
	struct hash_backet **index; 	/* Hash backet. */
	HS_rwlock_t *slot_rwlock; 		/* Hash backet rwlock */
	UINT32 size; 					/* Hash table size. */
	UINT32 (*hash_key) (void *); 			/* Key make function. */
	INT32 (*hash_cmp) (void *, void *); 			/* Data compare function. */
	void (*HS_HASH_Free) (void *); 			/* Data free function. */
	atomic_t count;
};

UINT32 ELFHash(void *p);

struct hash *HS_HASH_Create (UINT32 (*) (void *), INT32 (*) (void *, void *), void(*)(void *));
 
struct hash *HS_HASH_CreateSize (UINT32, UINT32 (*) (void *), INT32 (*) (void *, void *), void(*)(void *));

void *HS_HASH_Get (struct hash *, void *, void * (*) (void *), UINT32 hash_index);

INT32 HS_HASH_Insert (struct hash *, void *, void *);
 
INT32 HS_HASH_InsertWithLock(struct hash *, void *, void *, UINT32 hash_index);
 
void *HS_HASH_Lookup (struct hash *, void *, UINT32 hash_index);
 
void *HS_HASH_ReleaseWithoutLock(struct hash *hash, void *data, UINT32 hash_index);

void *HS_HASH_Release (struct hash *, void *);
 
void *HS_HASH_ReleaseWithLock(struct hash *, void *, UINT32 hash_index);

void HS_HASH_Iterate (struct hash *, void (*) (struct hash_backet *, void *), void *);

INT32 HS_HASH_IterateSlot(struct hash *hash, void *data, enum HS_HASH_ACTION_TYPE (*func)(void *backet_data, void *data, void *priv), void *priv);

void HS_HASH_Clean (struct hash *);

void HS_HASH_CleanWithoutFreeData(struct hash *hash);

void HS_HASH_Free (struct hash *);

UINT32 HS_HASH_PreRead(struct hash *hash, void *data);
 
void HS_HASH_PostRead(struct hash *hash, UINT32 index);

UINT32 HS_HASH_PreWrite(struct hash *hash, void *data);
 
void HS_HASH_PostWrite(struct hash *hash, UINT32 index);

void HS_HASH_PreWriteWithIndex(struct hash *hash, UINT32 uHashIdx);

void HS_HASH_PreReadWithIndex(struct hash *hash, UINT32 uHashIdx);

#define INVALID_DFA_STATE       0

#define DFA_MARKED 1
#define DFA_END 2

#define MAX_NODE_8_STAT_COUNT	255
#define MAX_NODE_16_STAT_COUNT	65535
#define MAX_ID_LEVEL  8

enum dfa_state_mode
{
    DFA_STATE_NORMAL,
    DFA_STATE_HALF,
    DFA_STATE_MAX
};

typedef struct {
	UCHAR next_state[256+2];	
	UINT32 id[MAX_ID_LEVEL];
	INT32 flag;
} DFA_STATE_8_S;

typedef struct {
	UCHAR next_state[128+2];
	UINT32 id[MAX_ID_LEVEL];
	INT32 flag;
} DFA_STATE_HALF_8_S;

typedef struct {
	UINT16 next_state[256+2];	
	UINT32 id[MAX_ID_LEVEL];
	INT32 flag;
} DFA_STATE_16_S;

typedef struct {
	UINT16 next_state[128+2];	
	UINT32 id[MAX_ID_LEVEL];
	INT32 flag;
} DFA_STATE_HALF_16_S;

typedef struct {
	UINT32 next_state[256+2];	
	UINT32 id[MAX_ID_LEVEL];
	INT32 flag;
} DFA_STATE_32_S;

typedef struct {
	UINT32 next_state[128+2];	
	UINT32 id[MAX_ID_LEVEL];
	INT32 flag;
} DFA_STATE_HALF_32_S;

typedef struct
{
    UINT32 	mode;
	UINT32 	size;
	UINT32 	init_state;
	UINT32  length;
	UCHAR 	dfa[0];
} DFA_S;

typedef struct dfa_ctx_
{
	UINT32 state;
	UINT32 offset;
} dfa_ctx;

static inline void INIT_DFA_CTX(dfa_ctx *pstCtx)
{
    pstCtx->state = INVALID_DFA_STATE;
    pstCtx->offset = 0;
}

/* Thomas Wang Integer Hash 
	http://www.concentric.net/~ttwang/tech/inthash.htm
*/
static inline UINT32 HASH_INT32(INT32 *key_p)
{
	INT32 key = *key_p;

	key = ~key + (key << 15);
	key ^= (key >> 12);
	key += (key << 2);
	key ^= (key >> 4);
	key *= 2057;
	key ^= (key >> 16); 
		
	return (UINT32)(key & 0x7fffffff);
}

void DFA_RevertByteSeq(DFA_S *pstGraph);

INT32 DFA_Scan(DFA_S *pstDfa, UCHAR *ucData, UINT32 uLen, INT32 iGreed, \
		dfa_ctx *pstCtx, UINT32 *puIdList, UINT32 uIdMax, UINT32 *uIdNum);

CHAR *HS_StrTok_R(CHAR *s, const CHAR *delim, CHAR **lasts);

void IAPF_DecodeHexChars(char *URL);

unsigned int IAPF_inet_addr(const char *ip_addr);

int IAPF_char_to_int(char* s);

void IAPF_int_to_char(int m, int n, char *s);

char *IAPF_inet_ntoa(UINT32 ina);

void IAPF_inet_ntoa_r(UINT32 ina, char *buf);

UINT32 IAPF_strtoul(const CHAR *nptr, CHAR **endptr, UINT32 base);

int IAPF_convert_words(char *convbuf, int len);

void HS_Qsort (void *base, UINT32 nel, UINT32 width, INT32 (*comp)(const void *, const void *));

#endif
