
SOURCES += external/zlib/adler32.c external/zlib/compress.c external/zlib/crc32.c external/zlib/deflate.c external/zlib/gzclose.c external/zlib/gzlib.c external/zlib/gzread.c external/zlib/gzwrite.c external/zlib/infback.c external/zlib/inffast.c external/zlib/inflate.c external/zlib/inftrees.c external/zlib/trees.c external/zlib/uncompr.c external/zlib/zutil.c
SOURCES += XP3Archive.cpp
SOURCES += StorageIntf.cpp
SOURCES += StorageImpl.cpp
SOURCES += storage.cpp
SOURCES += cxdec.c
INCFLAGS += -Iexternal/zlib
PROJECT_BASENAME = krxp3file
LDLIBS += -luuid

RC_LEGALCOPYRIGHT ?= Copyright (C) 2021-2021 Julian Uy; See details of license at license.txt, or the source code location.

include external/ncbind/Rules.lib.make
