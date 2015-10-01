
/* A Bison parser, made by GNU Bison 2.4.1.  */

/* Skeleton interface for Bison's Yacc-like parsers in C
   
      Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.
   
   This program is hs_free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.
   
   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */


/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     CONST_STRING = 258,
     RULE_HOOK_POS = 259,
     STRING_SESSION_APP = 260,
     STRING_P2P = 261,
     STRING_PORT_CLUSTER = 262,
     STRING_PORT_SERIES = 263,
     STEP = 264,
     PROTOCOL = 265,
     DST_IP = 266,
     SRC_IP = 267,
     DST_PORT = 268,
     SRC_PORT = 269,
     APP = 270,
     SIG_PRIO = 271,
     URL = 272,
     HISTORY = 273,
     NUMBER = 274,
     CONTINUE = 275,
     BREAK = 276,
     GOTO = 277,
     RETURN = 278,
     RECORD = 279,
     DETECT = 280,
     FUZZY_P2P_PORT_CLUSTER = 281,
     FUZZY_P2P_PORT_SERIES = 282,
     HS_TRUE = 283,
     HS_FALSE = 284,
     TCP = 285,
     UDP = 286,
     COMPARE = 287,
     AND = 288,
     OR = 289,
     NOT = 290,
     NEWLINE = 291,
     LEFT_BRACKET = 292,
     RIGHT_BRACKET = 293,
     SEMICOLON = 294,
     COMMA = 295,
     COLON = 296,
     QUESTION = 297
   };
#endif
/* Tokens.  */
#define CONST_STRING 258
#define RULE_HOOK_POS 259
#define STRING_SESSION_APP 260
#define STRING_P2P 261
#define STRING_PORT_CLUSTER 262
#define STRING_PORT_SERIES 263
#define STEP 264
#define PROTOCOL 265
#define DST_IP 266
#define SRC_IP 267
#define DST_PORT 268
#define SRC_PORT 269
#define APP 270
#define SIG_PRIO 271
#define URL 272
#define HISTORY 273
#define NUMBER 274
#define CONTINUE 275
#define BREAK 276
#define GOTO 277
#define RETURN 278
#define RECORD 279
#define DETECT 280
#define FUZZY_P2P_PORT_CLUSTER 281
#define FUZZY_P2P_PORT_SERIES 282
#define HS_TRUE 283
#define HS_FALSE 284
#define TCP 285
#define UDP 286
#define COMPARE 287
#define AND 288
#define OR 289
#define NOT 290
#define NEWLINE 291
#define LEFT_BRACKET 292
#define RIGHT_BRACKET 293
#define SEMICOLON 294
#define COMMA 295
#define COLON 296
#define QUESTION 297




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
{

/* Line 1676 of yacc.c  */
#line 26 "hs_yacc.y"

	int							integer;
	char						string[64];
	PBDL_ACTION_S 				action;
    PBDL_MATCH_UNIT_S			match_unit;
    TREE_NODE_S					tree_node;
    PBDL_SENTENCE_S				sentence;
    PBDL_STEP_S					step;
    PBDL_RULE_S					rule;
    PBDL_RULE_LIST_S			rule_list;
    PBDL_NUMERICAL_OPERATOR_E   nop;
    PBDL_LOGICAL_OPERATOR_E     lop;



/* Line 1676 of yacc.c  */
#line 152 "hs_yacc.h"
} YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif

extern YYSTYPE yylval;


