#ifndef __HS_PBDL_H_ 
#define __HS_PBDL_H_ 

#if MODE == USERSPACE
#include "hs_list.h"
#elif MODE == KERNELSPACE
#include <linux/list.h>
#endif

#include "hs_consts.h"
#include "hs_alg.h"
#include "hs_plugin.h"

#define MAX_APP_NAME_LENGTH		64
#define MAX_RULE_NAME_LENGTH	64
#define MAX_URL_LENGTH			128
#define MAX_EVENT_NAME_LENGTH 	64
#define MAX_EVENT_STRING_NUM    64
#define MAX_PARA_LENGTH 		64	

#define MAX_APP_PORT_STAT_NUM 8

#define MAX_EVENT_NAME_LENGTH	64
#define EVENT_TIMEOUT_DEFAULT 	600000 //600S

typedef struct _app_port_stat {
	UINT32 uAppId;
	UINT32 uCount;	
} APP_PORT_UNIT_S;

/**************************** Operator Definition ******************************/
/* æä½ç¬¦ç±»å?*/
typedef enum _pbdl_numerical_operator {
	NOP_UNKNOWN,
	NOP_EQ,
	NOP_NE,
	NOP_GREATER,
	NOP_LESS,
	NOP_GE,
	NOP_LE,
	NOP_MAX
} PBDL_NUMERICAL_OPERATOR_E;

typedef enum _pbdl_logical_operator {
	LOP_UNKNOWN,
	LOP_AND,
	LOP_OR,
	LOP_NOT,
	LOP_MAX
} PBDL_LOGICAL_OPERATOR_E;


/**************************** Match Unit Definition ***************************/
/* å¹éåç±»å?*/
typedef enum _pbdl_match_unit_type {
	MUT_UNKNOWN,
	MUT_PROTOCOL,
	MUT_DST_IP,
	MUT_SRC_IP,
	MUT_DST_PORT,
	MUT_SRC_PORT,
	MUT_APP,
	MUT_SIG_PRIO,
	MUT_URL,
	MUT_HISTORY,
	MUT_MAX
} PBDL_MATCH_UNIT_TYPE_E;

/* MatchUnit - APP */
typedef struct _pbdl_match_unit_app {
	CHAR arrAppName[MAX_APP_NAME_LENGTH];
	UINT32 uAppId;
} PBDL_MATCH_UNIT_APP_S;

/* MatchUnit - URL */
typedef struct _pbdl_match_unit_url {
	CHAR arrUrl[MAX_URL_LENGTH];
	DFA_S *pstDfaGraph;	
} PBDL_MATCH_UNIT_URL_S;

/* MatchUnit - HISTORY */
typedef struct _pbdl_match_unit_history {
	//CHAR arrName[MAX_EVENT_NAME_LENGTH];
	INT32 EventNameId;
	HS_time_t stTsDelta;
	boolean bValue;	
} PBDL_MATCH_UNIT_HISTORY_S;

typedef struct _pbdl_match {
	PBDL_MATCH_UNIT_TYPE_E enType;	
    PBDL_NUMERICAL_OPERATOR_E enNop;
	union {
		UINT32 	uProtocol;
		UINT32 	uDstIp;
		UINT32 	uSrcIp;
		UINT16 	usDstPort;
		UINT16 	usSrcPort;
		INT32 	nSigPrio;
		PBDL_MATCH_UNIT_APP_S 		stApp;
		PBDL_MATCH_UNIT_URL_S 		stUrl;
		PBDL_MATCH_UNIT_HISTORY_S 	stHistory;
	} unMatchUnit;		
} PBDL_MATCH_UNIT_S;

/********************* Match Tree Definition **********************************/
typedef enum {
	MATCH_NODE_UNKNOWN,
	MATCH_NODE_LOP,
	MATCH_NODE_MUT,
	MATCH_NODE_MAX
} PBDL_MATCH_NODE_TYPE_E; 

typedef struct _match_node {
	PBDL_MATCH_NODE_TYPE_E enType;
	union {
		PBDL_LOGICAL_OPERATOR_E enLop;
		PBDL_MATCH_UNIT_S stMatchUnit;		
	} unNode;
} PBDL_MATCH_NODE_S;

/********************* Action Definition **********************************/
/* Action Type */
typedef enum _pbdl_action_type {
	ACTION_UNKNOWN,
	ACTION_GOTO,
	ACTION_CONTINUE,
	ACTION_BREAK,
	ACTION_RETURN,
	ACTION_MAX
} PBDL_ACTION_TYPE_E;

/* Action - GOTO */
typedef struct _pbdl_action_goto {
	UINT32 uStepSeq;			
} PBDL_ACTION_GOTO_S;

/* Action - CONTINUE */
typedef struct _pbdl_action_continue {
	;
} PBDL_ACTION_CONTINUE_S;

typedef struct _pbdl_action_break {
	;
} PBDL_ACTION_BREAK_S;

/* Action - RETURN */
typedef struct _pbdl_action_return {
	;
} PBDL_ACTION_RETURN_S;

/* Step Action */
typedef struct _pbdl_action {
	PBDL_ACTION_TYPE_E enType;		
	union {
		PBDL_ACTION_GOTO_S		stGoto;	
		PBDL_ACTION_CONTINUE_S	stContinue;	
		PBDL_ACTION_BREAK_S		stBreak;	
		PBDL_ACTION_RETURN_S	stReturn;	
	} unAction;
} PBDL_ACTION_S;

/********************* Build-In Fucntion Definition ***************************/
/* Built-In Type */
typedef enum _pbdl_func_type {
	FUNC_UNKNOWN,
	FUNC_RECORD,
	FUNC_DETECT,
	FUNC_FUZZY_P2P_PORT_CLUSTER,
	FUNC_FUZZY_P2P_PORT_SERIES,
	FUNC_MAX
} PBDL_FUNC_TYPE_E;

#define PBDL_FUNC_UNKNOWN_STRING 		"UNKNOWN"
#define PBDL_FUNC_RECORD_STRING 		"RECORD"
#define PBDL_FUNC_MAX_STRING 			"MAX"

typedef struct _func_record_para{
	//CHAR arrEventName[MAX_EVENT_NAME_LENGTH];	
	UINT32  EventNameId;
	UINT32 uTimeoutDelta;	
} PBDL_FUNC_RECORD_PARA_S;

typedef struct _func_detect_para{
	CHAR arrAppName[MAX_APP_NAME_LENGTH];					
	UINT32 uAppId;
} PBDL_FUNC_DETECT_PARA_S;

#if 0
typedef enum _para_type {
	PARA_UNKNOWN,
	PARA_NUMBER,
	PARA_STRING,
	PARAM_MAX
} HS_PARA_TYPE_E;

typedef INT32 HS_PARA_NUMBER_T;
typedef CHAR HS_PARA_STRING_S[MAX_PARA_LENGTH];

typedef struct _pbdl_para {
	LIST_HEAD_S stList;
	HS_PARA_TYPE_E enType;
	union {
		HS_PARA_NUMBER_T nNumber;	
		HS_PARA_STRING_S stString;
	} unPara;
} HS_PARA_S;

/* Parameter List */
typedef struct _pbdl_para_list {
	UINT32 uParaNum;
	LIST_HEAD_S stParaList;
} PBDL_PARA_LIST_S;
#endif

typedef struct _pbdl_func {
	PBDL_FUNC_TYPE_E enType;
	union {
		PBDL_FUNC_RECORD_PARA_S stRecordPara;
		PBDL_FUNC_DETECT_PARA_S stDetectPara;
	} unPara;
} PBDL_FUNC_S;

/***************************** Sentence Definition ****************************/
/* Sentence Type */
typedef enum _pbdl_sentence_type {
	SENTENCE_UNKNOWN,
	SENTENCE_CASE,
	SENTENCE_FUNC,
	SENTENCE_ACTION,
	SENTENCE_MAX
} PBDL_SENTENCE_TYPE_E;

typedef struct _pbdl_sentence_case {
	TREE_NODE_S 		*pstMatchTreeRoot;		
	PBDL_ACTION_S		stTrueAction;
	PBDL_ACTION_S		stFalseAction;
} PBDL_SENTENCE_CASE_S; 

typedef struct _pbdl_sentence_func {
	PBDL_FUNC_S stFunc;
} PBDL_SENTENCE_FUNC_S;

typedef struct _pbdl_sentence_action {
	PBDL_ACTION_S stAction;
} PBDL_SENTENCE_ACTION_S;  

typedef struct _pbdl_sentence {
	LIST_HEAD_S stList;
	PBDL_SENTENCE_TYPE_E enType;
	union {
		PBDL_SENTENCE_CASE_S	stSentenceCase;	
		PBDL_SENTENCE_FUNC_S	stSentenceFunc;
		PBDL_SENTENCE_ACTION_S	stSentenceAction;
	} unSentence;
} PBDL_SENTENCE_S;

/***************************** Step Definition ********************************/
typedef struct _pbdl_step {
	LIST_HEAD_S stList;
	UINT32 uStepSeq;				/* sequence number the of this step. */
	UINT32 uSentenceNum;			/* number of sentences in this step, default may be One*/
	LIST_HEAD_S stSentenceList;		/* sentence list */
} PBDL_STEP_S;

/***************************** Rule Definition ********************************/
typedef struct _pbdl_rule {
	LIST_HEAD_S stList;
	HS_HOOK_E enHookPos;
	LIST_HEAD_S stStepList;
	UINT32 uStepNum;
} PBDL_RULE_S;

/**************************** Rule List Definition ****************************/
typedef struct _pbdl_rule_list {
	UINT32 uRuleNum;	
	LIST_HEAD_S stRuleList;
} PBDL_RULE_LIST_S;

/**************************** New Function  ****************************/
static inline PBDL_MATCH_NODE_S *PBDL_NewMatchNode(void)
{
	PBDL_MATCH_NODE_S *pstMatchNode = hs_malloc(sizeof(PBDL_MATCH_NODE_S));	
	if(NULL == pstMatchNode) {
		return NULL;		
	}

	pstMatchNode->enType = MATCH_NODE_UNKNOWN;

	return pstMatchNode;
}

static inline PBDL_SENTENCE_FUNC_S *PBDL_NewSentenceFunc(void) 
{
	PBDL_SENTENCE_FUNC_S *pstSentenceFunc = hs_malloc(sizeof(PBDL_SENTENCE_FUNC_S));	
	if(NULL == pstSentenceFunc) {
		return NULL;	
	}

	pstSentenceFunc->stFunc.enType = FUNC_UNKNOWN;

	return pstSentenceFunc;
}

static inline PBDL_SENTENCE_S *PBDL_NewSentence(void)
{
	PBDL_SENTENCE_S *pstSentence = hs_malloc(sizeof(PBDL_SENTENCE_S));
	if(NULL == pstSentence) {
		return NULL;	
	}

	INIT_LIST_HEAD(&pstSentence->stList);
	pstSentence->enType = SENTENCE_UNKNOWN;

	return pstSentence;
}

static inline PBDL_SENTENCE_S *PBDL_DupSentence(PBDL_SENTENCE_S *pstOldSentence)
{
    PBDL_SENTENCE_S *pstNewSentence;
    if(NULL == pstOldSentence) {
		return NULL;	
	}

	pstNewSentence = hs_malloc(sizeof(PBDL_SENTENCE_S));
	if(NULL == pstNewSentence) {
		return NULL;	
	}

	memcpy(pstNewSentence, pstOldSentence, sizeof(PBDL_SENTENCE_S));

	INIT_LIST_HEAD(&pstNewSentence->stList);

	return pstNewSentence;
}

static inline PBDL_STEP_S *PBDL_NewStep(void)
{
	PBDL_STEP_S *pstStep = hs_malloc(sizeof(PBDL_STEP_S));
	if(NULL == pstStep) {
		return NULL;	
	}

	pstStep->uStepSeq = 0;
	pstStep->uSentenceNum = 0;
	INIT_LIST_HEAD(&pstStep->stList);
	INIT_LIST_HEAD(&pstStep->stSentenceList);

	return pstStep;
}

static inline PBDL_STEP_S *PBDL_DupStep(PBDL_STEP_S *pstOldStep)
{
	PBDL_STEP_S *pstNewStep = hs_malloc(sizeof(PBDL_STEP_S));
	if(NULL == pstNewStep) {
		return NULL;	
	}

	pstNewStep->uStepSeq = pstOldStep->uStepSeq;
	pstNewStep->uSentenceNum = pstOldStep->uSentenceNum;

	INIT_LIST_HEAD(&pstNewStep->stList);
	list_replace(&pstOldStep->stSentenceList, &pstNewStep->stSentenceList);

	return pstNewStep;
}

static inline PBDL_RULE_S *PBDL_NewRule(void)
{
	PBDL_RULE_S *pstRule = hs_malloc(sizeof(PBDL_RULE_S));
	if(NULL == pstRule) {
		return NULL;	
	}

	INIT_LIST_HEAD(&pstRule->stList);
	INIT_LIST_HEAD(&pstRule->stStepList);
	pstRule->uStepNum = 0;
	pstRule->enHookPos = HS_HOOK_POST_DPI;

	return pstRule;
}

static inline PBDL_RULE_S *PBDL_DupRule(PBDL_RULE_S *pstOldRule)
{
	PBDL_RULE_S *pstNewRule = hs_malloc(sizeof(PBDL_RULE_S));
	if(NULL == pstNewRule) {
		return NULL;	
	}

	INIT_LIST_HEAD(&pstNewRule->stList);
	list_replace(&pstOldRule->stStepList, &pstNewRule->stStepList);
	pstNewRule->uStepNum = pstOldRule->uStepNum;
	pstNewRule->enHookPos = pstOldRule->enHookPos;

	return pstNewRule;
}

static inline PBDL_RULE_LIST_S *PBDL_NewRuleList(void)
{
	PBDL_RULE_LIST_S *pstRuleList = hs_malloc(sizeof(PBDL_RULE_LIST_S ));
	if(NULL == pstRuleList) {
		return NULL;	
	}

	pstRuleList->uRuleNum = 0;
	INIT_LIST_HEAD(&pstRuleList->stRuleList);

	return pstRuleList;
}

/**************************** Insert Function  ****************************/
static inline INT32 PBDL_InsertRule(PBDL_RULE_LIST_S *pstRuleList, PBDL_RULE_S *pstRule)
{
	if(NULL == pstRuleList || NULL == pstRule) {
		return HS_ERR;		
	}

	list_add(&pstRule->stList, &pstRuleList->stRuleList);

	return HS_OK;
}

static inline INT32 PBDL_InsertStep(PBDL_RULE_S *pstRule, PBDL_STEP_S *pstStep)
{
	if(NULL == pstRule || NULL == pstStep) {
		return HS_ERR;		
	}

	list_add(&pstStep->stList, &pstRule->stStepList);

	return HS_OK;
}

static inline INT32 PBDL_InsertSentence(PBDL_STEP_S *pstStep, PBDL_SENTENCE_S *pstSentence)
{
	if(NULL == pstStep || NULL == pstSentence) {
		return HS_ERR;	
	}

	pstStep->uSentenceNum++;
	/* add to current step */
	list_add(&pstSentence->stList, &pstStep->stSentenceList);

	return HS_OK;
}

INT32 HS_BHV_Load(const CHAR *pRuleFileName);

#endif
