This repo contains Alexander Roshal's unrar freeware with
some additions.  See license.txt .

Don't contact Alexander regarding possible bugs in the
source code I have modified.  Code is provided as is,
no warranty of any kind.

You can modify unrar.spec to add proper flags:
%build
make %{?_smp_mflags} -f makefile unrar \
  CXX="%{__cxx}" CXXFLAGS="$RPM_OPT_FLAGS -fPIC -DPIC" LDFLAGS="-Wl,-z,relro -Wl,-z,now -pie -lseccomp" STRIP=: RANLIB=ranlib
make %{?_smp_mflags} -f makefile lib \
  CXX="%{__cxx}" CXXFLAGS="$RPM_OPT_FLAGS -fPIC -DPIC" LDFLAGS="-Wl,-z,relro -Wl,-z,now -lseccomp" STRIP=: RANLIB=ranlib
