USERSPACE=1
KERNELSPACE=2
MODE=1

PDE_PACKET=1
PDE_SESSION=2


ENG_VERSION_VALUE=HyperScan-4.1.2
ENG_RELEASE_TIME_VALUE=$(shell date +%F)

ifeq (${MODE}, ${USERSPACE})
###########################################################################
#						     user space                                   #
###########################################################################
PDE_MODE=1
#include ${PWD}/Makefile.inc

CC      = gcc 
STRIP   = strip
AR      = ar
RANLIB  = ranlib
PWD     = $(shell pwd)
ROOT    = ${PWD}/../
LIBMXML = ${ROOT}/libmxml
LIBZ    = ${ROOT}/zlib
LIBZLOG = ${ROOT}/zlog/src
OPENSSL = /usr/local/ssl/include/
LIBNIDS = ${ROOT}/libnids/src
LIBPCAP	= ${ROOT}/libpcap

CFLAGS     += -fPIC 

#CFLAGS     += -DDEBUG_MODE

#CFLAGS += -O2 
CFLAGS += -g

CFLAGS += -DNO_CHECK_LICENSE_HARDWARE 

CFLAGS += -DIAPF_YES=1 -DIAPF_NO=0 -DHS_BIG_ENDIAN=0 -DHS_LITTLE_ENDIAN=1

CFLAGS += -DPDE_PACKET=${PDE_PACKET} -DPDE_SESSION=${PDE_SESSION} -DPDE_MODE=${PDE_MODE}

CFLAGS += -DMODE=${MODE} -DUSERSPACE=${USERSPACE} -DKERNELSPACE=${KERNELSPACE} -DHTTP_DFA_ID_LENGTH=2 

CFLAGS  += -std=gnu99 -DENG_VERSION="\"${ENG_VERSION_VALUE}\"" -DENG_RELEASE_TIME="\"${ENG_RELEASE_TIME_VALUE}\"" 

CFLAGS += -I ${PWD} -I ../include -I ../include/libz  -I ${LIBZLOG} -I ${OPENSSL} -I ${LIBNIDS} -I ${LIBPCAP}

LDFLAGS =  -L/usr/lib -lpthread -lm 

SRCS_1 = ${SRCS} \
		hs_account.c	\
		hs_mobile_info.c \
		dpi.c \

OBJS = $(SRCS:.c=.o)
OBJS_1 = $(SRCS_1:.c=.o)

all:hs

.c.o:
	${CC} $(CFLAGS) -o $@ -c $< 

%.d:%.c
	@set -e; rm -f $@; $(CC) -MM $< $(CFLAGS) > $@.$$$$; \
		sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
		rm -f $@.$$$$

-include $(OBJS_1:.o=.d)

hs: ${OBJS_1}

clean:
	for dir in ${SUBDIR}; do ${MAKE} clean -C $${dir} || exit 1; done
	rm -rf *.o *.d 
else
###########################################################################
#						     kernel space                                 #
###########################################################################
PDE_MODE=1

ROOT_DIR=${PWD}/../
KVERSION=`uname -r`
#KERNEL_SRC=/lib/modules/${KVERSION}/build
#KERNEL_SRC=/root/linux-2.6.32.27
KERNEL_SRC=/root/kernel/linux-2.6.32.27-hyperscan

EXTRA_CFLAGS += -I ${ROOT_DIR}/include 
EXTRA_CFLAGS += -I ${ROOT_DIR}/include/libz

#EXTRA_CFLAGS += -DDEBUG_MODE

EXTRA_CFLAGS += -DENG_VERSION="\"${ENG_VERSION_VALUE}\"" -DENG_RELEASE_TIME="\"${ENG_RELEASE_TIME_VALUE}\""

EXTRA_CFLAGS += -DIAPF_YES=1 -DIAPF_NO=0 -DBIG_ENDIAN=0 -DLITTLE_ENDIAN=1

EXTRA_CFLAGS += -DMODE=${MODE} -DUSERSPACE=${USERSPACE} -DKERNELSPACE=${KERNELSPACE} -DHTTP_DFA_ID_LENGTH=2 ${INCLUDE}

EXTRA_CFLAGS += -DPDE_PACKET=${PDE_PACKET} -DPDE_SESSION=${PDE_SESSION} -DPDE_MODE=${PDE_MODE}

EXTRA_CFLAGS += -g

EXTRA_CFLAGS += -D_LARGEFILE64_SOURCE=1 -DHAVE_HIDDEN

obj-m := hyperscan.o 

hyperscan-objs:= hs_main.o \
	hs_core.o \
	hs_alg.o \
	hs_plugin.o \
	hs_dfi.o \
	hs_ftp.o \
	hs_cnt.o \
	hs_http.o \
	hs_sip.o \
	hs_fake.o \
	hs_host.o \
	hs_dns.o \
	hs_expect.o \
	hs_bhv.o \
	hs_lex.o \
	hs_yacc.o \
	libz/adler32.o   libz/crc32.o  libz/gzclose.o  libz/gzread.o   libz/infback.o  libz/inflate.o   libz/trees.o    libz/zutil.o libz/compress.o  libz/deflate.o  libz/gzlib.o    libz/gzwrite.o  libz/inffast.o  libz/inftrees.o  libz/uncompr.o

all:
	make -C ${KERNEL_SRC} M=`pwd` modules

clean:
	make -C ${KERNEL_SRC} M=`pwd` clean


endif
