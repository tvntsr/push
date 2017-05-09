# $Id$
#
# acc_radius module makefile
#
#
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=push.so

DEFS += -I$(LOCALBASE)/ssl/include
LIBS += -L$(LOCALBASE)/lib -L$(LOCALBASE)/ssl/lib \
        -L$(LOCALBASE)/lib64 -L$(LOCALBASE)/ssl/lib64 \
        -lssl -lcrypto

CFLAGS+=-g3
#include ../../Makefile.push

DEFS+=-DKAMAILIO_MOD_INTERFACE

SERLIBPATH=../../lib
SER_LIBS+=$(SERLIBPATH)/srdb1/srdb1

include ../../Makefile.modules
