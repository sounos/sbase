lib_LTLIBRARIES = libsbase.la
libsbase_la_SOURCES = conn.h \
message.h \
procthread.h \
sbase.h \
service.h \
conn.c \
message.c \
procthread.c \
sbase.c \
service.c \
utils/chunk.h \
utils/chunk.c \
utils/mmblock.h \
utils/mmblock.c \
utils/mutex.h \
utils/logger.h \
utils/logger.c \
utils/evtimer.h \
utils/evtimer.c \
utils/xssl.h 	\
utils/xmm.h 	\
utils/xmm.c 	\
utils/stime.h 	\
utils/stime.c 	

libsbase_la_CPPFLAGS = -I utils -D_FILE_OFFSET_BITS=64 -Wall
libsbase_la_LDFLAGS = -levbase
include_HEADERS = sbase.h

sbin_PROGRAMS = xhttpd lechod lhttpd nowd

xhttpd_SOURCES = xhttpd.c iniparser.h iniparser.c utils/http.h utils/http.c \
				 utils/mutex.h utils/mtrie.h utils/mtrie.c utils/stime.h utils/stime.c \
				utils/logger.h utils/logger.c utils/xmm.h utils/xmm.c \
				utils/mime.h utils/mime.c 
xhttpd_CPPFLAGS = -I utils -D_FILE_OFFSET_BITS=64 -Wall 
xhttpd_LDADD = libsbase.la
xhttpd_LDFLAGS = -static

lechod_SOURCES = lechod.c iniparser.h iniparser.c
lechod_CPPFLAGS = -I utils -D_FILE_OFFSET_BITS=64 -Wall 
lechod_LDADD = libsbase.la
lechod_LDFLAGS = -static

nowd_SOURCES = nowd.c iniparser.h iniparser.c
nowd_CPPFLAGS = -I utils -D_FILE_OFFSET_BITS=64 -Wall 
nowd_LDADD = libsbase.la
nowd_LDFLAGS = -static

lhttpd_SOURCES = lhttpd.c 
lhttpd_CPPFLAGS = -I utils -D_FILE_OFFSET_BITS=64 -Wall 
lhttpd_LDADD = libsbase.la
lhttpd_LDFLAGS = -static

bin_PROGRAMS = wbenchmark
wbenchmark_SOURCES = wbenchmark.c utils/mutex.h utils/logger.h utils/logger.c \
					utils/xmm.h utils/xmm.c utils/timer.h
wbenchmark_CPPFLAGS = -I utils/ -Wall 
wbenchmark_LDADD = libsbase.la
wbenchmark_LDFLAGS = -static
