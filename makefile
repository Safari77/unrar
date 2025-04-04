#
# Makefile for UNIX - unrar

# Linux using GCC
# 2024.08.19: -march=native isn't recognized on some platforms such as RISCV64.
# Thus we removed it. Clang ARM users can add -march=armv8-a+crypto to enable
# ARM NEON crypto.
CXX=c++
CXXFLAGS=-O2 -std=c++11 -Wno-switch -Wno-dangling-else
LIBFLAGS=-fPIC
DEFINES=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DRAR_SMP
STRIP=strip
AR=ar
LDFLAGS=-pthread -lseccomp
DESTDIR=/usr

##########################

COMPILE=$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(DEFINES)
LINK=$(CXX)

WHAT=UNRAR

UNRAR_OBJ=filestr.o recvol.o rs.o scantree.o qopen.o
LIB_OBJ=filestr.o scantree.o dll.o qopen.o

OBJECTS=rar.o strlist.o strfn.o pathfn.o smallfn.o global.o file.o filefn.o filcreat.o \
	archive.o arcread.o unicode.o system.o crypt.o crc.o rawread.o encname.o \
	resource.o match.o timefn.o rdwrfn.o consio.o options.o errhnd.o rarvm.o secpassword.o \
	rijndael.o getbits.o sha1.o sha256.o blake2s.o hash.o extinfo.o extract.o volume.o \
	list.o find.o unpack.o headers.o threadpool.o rs16.o cmddata.o ui.o largepage.o

.cpp.o:
	$(COMPILE) -D$(WHAT) -c $<

all:	unrar

install:	install-unrar

uninstall:	uninstall-unrar

clean:
	@rm -f *.bak *~
	@rm -f $(OBJECTS) $(UNRAR_OBJ) $(LIB_OBJ)
	@rm -f unrar libunrar.*

# We removed 'clean' from dependencies, because it prevented parallel
# 'make -Jn' builds.

unrar:	$(OBJECTS) $(UNRAR_OBJ)
	$(LINK) -o unrar $(LDFLAGS) $(OBJECTS) $(UNRAR_OBJ) $(LIBS)	

sfx:	WHAT=SFX_MODULE
sfx:	$(OBJECTS)
	@rm -f default.sfx
	$(LINK) -o default.sfx $(LDFLAGS) $(OBJECTS)

lib:	WHAT=RARDLL
lib:	CXXFLAGS+=$(LIBFLAGS)
lib:	$(OBJECTS) $(LIB_OBJ)
	$(LINK) -shared -o libunrar.so $(LDFLAGS) $(OBJECTS) $(LIB_OBJ) $(LIBS)
	$(AR) rcs libunrar.a $(OBJECTS) $(LIB_OBJ)

install-unrar:
			install -D unrar $(DESTDIR)/bin/unrar

uninstall-unrar:
			rm -f $(DESTDIR)/bin/unrar

install-lib:
		install libunrar.so $(DESTDIR)/lib
		install libunrar.a $(DESTDIR)/lib

uninstall-lib:
		rm -f $(DESTDIR)/lib/libunrar.so
