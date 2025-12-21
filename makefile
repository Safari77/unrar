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

arccmt.o: arccmt.cpp
archive.o: archive.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp arccmt.cpp
arcread.o: arcread.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
blake2s.o: blake2s.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp blake2s_sse.cpp blake2sp.cpp
blake2sp.o: blake2sp.cpp
blake2s_sse.o: blake2s_sse.cpp
cmddata.o: cmddata.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp cmdfilter.cpp cmdmix.cpp cmd_security.cpp \
 cmd_security.hpp
cmdfilter.o: cmdfilter.cpp
cmdmix.o: cmdmix.cpp
cmd_security.o: cmd_security.cpp rar.hpp raros.hpp rartypes.hpp os.hpp \
 version.hpp rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp \
 errhnd.hpp secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp \
 blake2s.hpp hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp \
 headers.hpp pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp \
 find.hpp scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp \
 match.hpp cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp cmd_security.hpp
coder.o: coder.cpp
consio.o: consio.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp log.cpp
crc.o: crc.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
crypt1.o: crypt1.cpp
crypt2.o: crypt2.cpp
crypt3.o: crypt3.cpp
crypt5.o: crypt5.cpp
crypt.o: crypt.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp crypt1.cpp crypt2.cpp crypt3.cpp crypt5.cpp
dll.o: dll.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
encname.o: encname.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
errhnd.o: errhnd.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
extinfo.o: extinfo.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp hardlinks.cpp win32stm.cpp uowners.cpp ulinks.cpp
extract.o: extract.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
filcreat.o: filcreat.cpp rar.hpp raros.hpp rartypes.hpp os.hpp \
 version.hpp rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp \
 errhnd.hpp secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp \
 blake2s.hpp hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp \
 headers.hpp pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp \
 find.hpp scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp \
 match.hpp cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
file.o: file.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
filefn.o: filefn.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
filestr.o: filestr.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
find.o: find.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
getbits.o: getbits.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
global.o: global.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
hardlinks.o: hardlinks.cpp
hash.o: hash.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
headers.o: headers.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
isnt.o: isnt.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
largepage.o: largepage.cpp rar.hpp raros.hpp rartypes.hpp os.hpp \
 version.hpp rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp \
 errhnd.hpp secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp \
 blake2s.hpp hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp \
 headers.hpp pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp \
 find.hpp scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp \
 match.hpp cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
list.o: list.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
log.o: log.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
match.o: match.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
model.o: model.cpp
motw.o: motw.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
options.o: options.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
pathfn.o: pathfn.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
qopen.o: qopen.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
rar.o: rar.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
rarpch.o: rarpch.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
rarvm.o: rarvm.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
rawread.o: rawread.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
rdwrfn.o: rdwrfn.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
recvol3.o: recvol3.cpp
recvol5.o: recvol5.cpp
recvol.o: recvol.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp recvol3.cpp recvol5.cpp
resource.o: resource.cpp rar.hpp raros.hpp rartypes.hpp os.hpp \
 version.hpp rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp \
 errhnd.hpp secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp \
 blake2s.hpp hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp \
 headers.hpp pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp \
 find.hpp scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp \
 match.hpp cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
rijndael.o: rijndael.cpp rar.hpp raros.hpp rartypes.hpp os.hpp \
 version.hpp rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp \
 errhnd.hpp secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp \
 blake2s.hpp hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp \
 headers.hpp pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp \
 find.hpp scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp \
 match.hpp cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
rs16.o: rs16.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
rs.o: rs.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
scantree.o: scantree.cpp rar.hpp raros.hpp rartypes.hpp os.hpp \
 version.hpp rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp \
 errhnd.hpp secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp \
 blake2s.hpp hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp \
 headers.hpp pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp \
 find.hpp scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp \
 match.hpp cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
secpassword.o: secpassword.cpp rar.hpp raros.hpp rartypes.hpp os.hpp \
 version.hpp rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp \
 errhnd.hpp secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp \
 blake2s.hpp hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp \
 headers.hpp pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp \
 find.hpp scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp \
 match.hpp cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
sha1.o: sha1.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
sha256.o: sha256.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
smallfn.o: smallfn.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
strfn.o: strfn.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
strlist.o: strlist.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
suballoc.o: suballoc.cpp
system.o: system.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
threadmisc.o: threadmisc.cpp
threadpool.o: threadpool.cpp rar.hpp raros.hpp rartypes.hpp os.hpp \
 version.hpp rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp \
 errhnd.hpp secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp \
 blake2s.hpp hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp \
 headers.hpp pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp \
 find.hpp scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp \
 match.hpp cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
timefn.o: timefn.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
uicommon.o: uicommon.cpp
uiconsole.o: uiconsole.cpp
ui.o: ui.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp uicommon.cpp uiconsole.cpp
uisilent.o: uisilent.cpp
ulinks.o: ulinks.cpp
unicode.o: unicode.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
unpack15.o: unpack15.cpp
unpack20.o: unpack20.cpp rar.hpp raros.hpp rartypes.hpp os.hpp \
 version.hpp rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp \
 errhnd.hpp secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp \
 blake2s.hpp hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp \
 headers.hpp pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp \
 find.hpp scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp \
 match.hpp cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
unpack30.o: unpack30.cpp
unpack50.o: unpack50.cpp
unpack50frag.o: unpack50frag.cpp
unpack50mt.o: unpack50mt.cpp
unpack.o: unpack.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp coder.cpp suballoc.cpp model.cpp unpackinline.cpp \
 unpack15.cpp unpack20.cpp unpack30.cpp unpack50.cpp unpack50frag.cpp
unpackinline.o: unpackinline.cpp
uowners.o: uowners.cpp
volume.o: volume.cpp rar.hpp raros.hpp rartypes.hpp os.hpp version.hpp \
 rardefs.hpp rarlang.hpp loclang.hpp rawint.hpp unicode.hpp errhnd.hpp \
 secpassword.hpp strlist.hpp timefn.hpp sha1.hpp sha256.hpp blake2s.hpp \
 hash.hpp options.hpp rijndael.hpp crypt.hpp headers5.hpp headers.hpp \
 pathfn.hpp strfn.hpp file.hpp crc.hpp filefn.hpp filestr.hpp find.hpp \
 scantree.hpp getbits.hpp rdwrfn.hpp qopen.hpp archive.hpp match.hpp \
 cmddata.hpp ui.hpp filcreat.hpp consio.hpp system.hpp log.hpp \
 rawread.hpp encname.hpp resource.hpp compress.hpp rarvm.hpp model.hpp \
 coder.hpp suballoc.hpp threadpool.hpp largepage.hpp unpack.hpp \
 extinfo.hpp extract.hpp list.hpp rs.hpp rs16.hpp recvol.hpp volume.hpp \
 smallfn.hpp global.hpp
win32acl.o: win32acl.cpp
win32lnk.o: win32lnk.cpp
win32stm.o: win32stm.cpp
