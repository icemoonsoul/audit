###########################################################################
#						      user space                                  #
###########################################################################
CC      	= gcc 
STRIP   	= strip
AR      	= ar
RANLIB  	= ranlib
PWD 		= $(shell pwd)
HS_INCLUDE	= ${PWD}/include
LIBHS		= ${PWD}/source
LIBNIDS 	= ${PWD}/libnids/src
LIBXML 		= ${PWD}/libmxml
LIBPCAP		= ${PWD}/libpcap
LIBCRYPTO	= ${PWD}/libcrypto
ZLIB  		= ${PWD}/zlib
LIBZLOG		= ${PWD}/zlog/src
OPENSSL		= /usr/local/ssl/include/

CFLAGS 	= -g
#CFLAGS 	= -std=gnu99 -Wall -O2

CFLAGS+=-DHS_PRINTT_STAT

CFLAGS 	+=  -I ${PWD} -I ${HS_INCLUDE} -I ${LIBNIDS} -I ${ZLIB} -I ${LIBPCAP} -I ${LIBZLOG} -I ${OPENSSL}

#LDFLAGS =  -L/usr/lib -lpthread -lm -lpcap -lhs
LDFLAGS =  -L/usr/lib -L/usr/local/lib/ -lpthread -lm

SRCS = 	hyperscan.c main.c

OBJS = $(SRCS:.c=.o)

LIBDIR 		= ./source ./libnids ./zlog

SUBLIBS 	= ${LIBHS}/libhs.a ${LIBNIDS}/libnids.a  ${ZLIB}/libz.a  \
			  ${LIBPCAP}/libpcap.a ${LIBCRYPTO}/libcrypto.a ${LIBZLOG}/libzlog.a

.PHONY: target lib hyperscan clean cleanlib

all: x86 lib dpi hyperscan

x86:
	./x86_x64.sh -r
	#make target

x64:
	./x86_x64.sh 
	#make target

lib:
	@for dir in ${LIBDIR}; do ${MAKE} -C $${dir} ; done

cleanlib: ${LIBDIR}
	@for dir in ${LIBDIR}; do ${MAKE} clean -C $${dir} ; done

target: 
	make lib
	make dpi

hyperscan:hyperscan.o ${LIBHS}/hs_account.o ${LIBHS}/hs_mobile_info.o
	${CC} -o hyperscan hyperscan.o ${LIBHS}/hs_account.o ${LIBHS}/hs_mobile_info.o ${CFLAGS} ${LDFLAGS} ${SUBLIBS} 

dpi: main.o ${LIBHS}/dpi.o ${LIBHS}/hs_account.o ${LIBHS}/hs_mobile_info.o ${SUBLIBS}
	${CC} -o dpi main.o ${LIBHS}/dpi.o ${LIBHS}/hs_account.o ${LIBHS}/hs_mobile_info.o ${CFLAGS} ${LDFLAGS} ${SUBLIBS} 
	${STRIP} dpi

.c.o:
	${CC} $(CFLAGS) -o $@ -c $< 

%.d:%.c
	@set -e; rm -f $@; $(CC) -MM $< $(CFLAGS) > $@.$$$$; \
		sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
		rm -f $@.$$$$

clean: 
	make cleanlib
	rm -rf *.o dpi hyperscan
