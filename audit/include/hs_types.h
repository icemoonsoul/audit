#ifndef __HS_TYPES_H_
#define __HS_TYPES_H_

#if MODE == USERSPACE
#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "zlog.h"
#elif MODE == KERNELSPACE
#include <linux/types.h>
#include <linux/time.h>
#endif

#if MODE == USERSPACE
#define IAPF_USR_DEF(type, var)            type var
#define IAPF_KERNEL_DEF(type, var)

#define IAPF_USR_DEF_INIT(type, var, val)       type var = val
#define IAPF_KERNEL_DEF_INIT(type, var, val) 
#elif MODE == KERNELSPACE
#define IAPF_USR_DEF(type, var)        
#define IAPF_KERNEL_DEF(type, var)              type var

#define IAPF_USR_DEF_INIT(type, var, val)        
#define IAPF_KERNEL_DEF_INIT(type, var, val)    type var = val
#endif

#if MODE == USERSPACE
extern zlog_category_t *g_pstZc;
#endif

#if MODE == USERSPACE
#define HS_PRINT                    printf
#define HS_FATAL(fmt, arg...)       zlog_fatal(g_pstZc, fmt, ##arg)
#define HS_WARN(fmt, arg...)        zlog_warn(g_pstZc, fmt, ##arg)
#define HS_INFO(fmt, arg...)        zlog_info(g_pstZc, fmt, ##arg)
#define HS_DEBUG(fmt, arg...)       zlog_debug(g_pstZc, fmt, ##arg)
#elif MODE == KERNELSPACE
#define HS_PRINT    printk
#define HS_FATAL(fmt, arg...)       printk(fmt, ##arg)
#define HS_WARN(fmt, arg...)        printk(fmt, ##arg)
#define HS_INFO(fmt, arg...)        printk(fmt, ##arg)
#define HS_DEBUG(fmt, arg...)       
typedef struct list_head LIST_HEAD_S;
#endif

typedef char 						CHAR;
typedef char                      	INT8;
typedef char                      	s8;
typedef unsigned char             	UCHAR;
typedef unsigned char             	UINT8;
typedef unsigned char             	u8;
typedef short 						SHORT;
typedef short                     	INT16;
typedef short                     	s16;
typedef unsigned short 				USHORT;
typedef unsigned short            	UINT16;
typedef unsigned short            	u16;
typedef int 					  	INT;
typedef int                       	INT32;
typedef int                       	s32;
typedef unsigned int 			  	UINT;
typedef unsigned int              	UINT32;
typedef unsigned int              	u32;
typedef long                      	LONG;
typedef unsigned long             	ULONG;
typedef long long 		  	        INT64;
typedef long long 		  	        s64;
typedef unsigned long long 		  	UINT64;
typedef unsigned long long 		  	u64;
typedef float                     	FLOAT;
typedef double                    	DOUBLE;

typedef int                       	BOOL;
typedef void                      	VOID;
typedef int                       	ERRCODE;

typedef UINT32 HS_APPID_T;

#ifndef boolean
#define boolean INT32
#endif

#ifndef TRUE
#define TRUE	(1==1)
#endif

#ifndef FALSE
#define FALSE	(1==0)
#endif

#if MODE == USERSPACE
#define HS_rwlock_t					pthread_rwlock_t 
#define HS_rwlock_init(lock)		pthread_rwlock_init(lock, NULL)
#define HS_rwlock_destroy(lock)		pthread_rwlock_destroy(lock)
#define HS_read_lock(lock)			pthread_rwlock_rdlock(lock)
#define HS_write_lock(lock)			pthread_rwlock_wrlock(lock)
#define HS_read_unlock(lock) 		pthread_rwlock_unlock(lock)
#define HS_write_unlock(lock) 		pthread_rwlock_unlock(lock)
#define HS_read_trylock(lock)	    pthread_rwlock_tryrdlock(lock)
#define HS_write_trylock(lock)		pthread_rwlock_trywrlock(lock)
#elif MODE == KERNELSPACE
#define HS_rwlock_t					rwlock_t 
#define HS_rwlock_init(lock)	    rwlock_init(lock) 	
#define HS_rwlock_destroy(lock)		
#define HS_read_lock(lock)			read_lock(lock)
#define HS_write_lock(lock)			write_lock(lock)
#define HS_read_unlock(lock) 		read_unlock(lock)
#define HS_write_unlock(lock) 		write_unlock(lock)
#define HS_read_trylock				read_trylock(lock)
#define HS_write_trylock			write_trylock(lock)
#endif

#if MODE == USERSPACE 
typedef INT32                                   IAPF_FILE;
#define IAPF_Open(file, flags, mode, fs)        open(file, flags, mode)
#define IAPF_Read(file, buff, len, pOffset)     read(file, buff, len)
#define IAPF_Write(file, buff, len, pOffset)    write(file, buff, len)
#define IAPF_Close(file, fs)                    close(file)
#define IAPF_FileErr(file)                      (file < 0)
#elif MODE == KERNELSPACE
typedef struct file *                           IAPF_FILE;
#define IAPF_Open(file, flags, mode, fs)        IAPF_Open_Imp(file, flags, mode, fs)
#define IAPF_Read(file, buff, len, pOffset)     vfs_read(file, buff, len, pOffset)
#define IAPF_Write(file, buff, len, pOffset)    vfs_write(file, buff, len, pOffset)
#define IAPF_Close(file, fs)                    IAPF_Close_Imp(file, fs)
#define IAPF_FileErr(file)                      IS_ERR(file)
//#define HS_rename 		rename
#endif

#if 0
#if MODE == USERSPACE
#define IAPF_GzFile                             gzFile
#define IAPF_GzOpen                             gzopen
#define IAPF_GzRead                             gzread
#define IAPF_GzClose                            gzclose
#elif MODE == KERNELSPACE
#define IAPF_GzFile                             gzFile
#define IAPF_GzOpen                             zlib_gzopen
#define IAPF_GzRead                             zlib_gzread
#define IAPF_GzClose                            zlib_gzclose
#endif
#endif

#define IAPF_GzFile                             gzFile
#define IAPF_GzOpen                             gzopen
#define IAPF_GzRead                             gzread
#define IAPF_GzClose                            gzclose

typedef struct timeval HS_time_t;

#if MODE == USERSPACE
#define atomic_t		        INT32
#define atomic_read(v)	        (*(v))
#define atomic_set(v,i)	        ((*(v))=(i))
#define atomic_inc(v)	        ((*v)++)
#define atomic_dec(v)	        ((*v)--)
#define atomic_add(i,v)	        ((*v)+=(i))
#define atomic_sub(i,v)         ((*v)-=(i))
#define atomic_inc_return(v)    (++(*v))
#define atomic_dec_return(v)    (--(*v))
#endif

#if MODE == USERSPACE
#define EXPORT_SYMBOL(func)
#endif

typedef void *(*MALLOC_FUNC)(size_t);
typedef void *(*CALLOC_FUNC)(size_t, size_t);
typedef void *(*REALLOC_FUNC)(void *, size_t);
typedef void  (*FREE_FUNC)(void *);

#endif
