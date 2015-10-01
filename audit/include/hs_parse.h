#ifndef _HS_PARSE_H_
#define _HS_PARSE_H_

#include "hs_consts.h"
#include "hs_types.h"

INT32 IAPF_LoadFile(const CHAR *pcFileName, CHAR *pcBuff, UINT32 ulLen);
UINT32 GetLineFromBuffer(CHAR *pcSrc, UINT32 uSrcLen, UINT32 *puSrcOffset, CHAR *pcDst, UINT32 uDstLen);
INT32 IsBlankChar(CHAR c);
CHAR *GetFirstNonBlankChar(CHAR *pcBuff, INT32 uLen);
CHAR *GetFirstNonBlankCharRev(CHAR *pcBuff, INT32 uLen);

#endif
