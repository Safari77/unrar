%global toolchain clang
Name:           unrar
Version:        7.2.4
Release:        666%{?dist}
Summary:        Utility for extracting, testing and viewing RAR archives - contains seccomp and other hardening features
License:        Freeware with further limitations
Group:          Applications/Archiving
URL:            https://www.rarlab.com/rar_add.htm
Source0:        https://www.rarlab.com/rar/unrarsrc-%{version}.tar.gz
# Man page from Debian
Source1:        unrar-nonfree.1
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Patch0:         unrar-7.2.4-local.patch

Requires(post): chkconfig
Requires(preun): chkconfig


%description
The unrar utility is a freeware program for extracting, testing and
viewing the contents of archives created with the RAR archiver version
1.50 and above.


%package -n libunrar
Summary:        Decompress library for RAR v3 archives
Group:          System Environment/Libraries

%description -n libunrar
The libunrar library allows programs linking against it to decompress
existing RAR v3 archives.

%package -n libunrar-devel
Summary:        Development files for libunrar
Group:          Development/Libraries
Requires:       libunrar%{_isa} = %{version}-%{release}
Provides:       libunrar3-%{version}

%description -n libunrar-devel
The libunrar-devel package contains libraries and header files for
developing applications that use libunrar.


%prep
%autosetup -p1 -n %{name}
cp -p %SOURCE1 .


%build
%global optflags %{optflags} -fsanitize=safe-stack,scudo
%global build_ldflags %{build_ldflags} -fsanitize=safe-stack,scudo
make %{?_smp_mflags} -f makefile unrar \
  CXX=clang++ CXXFLAGS="$RPM_OPT_FLAGS -fPIC -DPIC" LDFLAGS="-fsanitize=safe-stack,scudo -Wl,-z,relro -Wl,-z,now -pie -lseccomp" STRIP=: RANLIB=ranlib
make %{?_smp_mflags} -f makefile lib \
  CXX=clang++ CXXFLAGS="$RPM_OPT_FLAGS -fPIC -DPIC" LDFLAGS="-fsanitize=safe-stack,scudo -Wl,-z,relro -Wl,-z,now -lseccomp" STRIP=: RANLIB=ranlib

%install
rm -rf %{buildroot}
install -Dpm 755 unrar %{buildroot}%{_bindir}/unrar-nonfree
install -Dpm 644 unrar-nonfree.1 %{buildroot}%{_mandir}/man1/unrar-nonfree.1
install -Dpm 755 libunrar.so %{buildroot}%{_libdir}/libunrar.so
mkdir -p -m 755 %{buildroot}/%{_includedir}/unrar
for i in *.hpp; do
    install -Dpm 644 $i %{buildroot}/%{_includedir}/unrar
done

# handle alternatives
touch %{buildroot}%{_bindir}/unrar

# RPM Macros support
mkdir -p %{buildroot}%{_sysconfdir}/rpm
cat > %{buildroot}%{_sysconfdir}/rpm/macros.unrar << EOF
# unrar RPM Macros
%unrar_version    %{version}
EOF
touch -r license.txt %{buildroot}%{_sysconfdir}/rpm/macros.unrar


%clean
rm -rf %{buildroot}


%post
%{_sbindir}/alternatives \
    --install %{_bindir}/unrar unrar %{_bindir}/unrar-nonfree 50 \
    --slave %{_mandir}/man1/unrar.1.gz unrar.1.gz \
    %{_mandir}/man1/unrar-nonfree.1.gz || :

%preun
if [ "$1" -eq 0 ]; then
  %{_sbindir}/alternatives \
      --remove unrar %{_bindir}/unrar-nonfree || :
fi

%post -n libunrar -p /sbin/ldconfig


%postun -n libunrar -p /sbin/ldconfig


%files
%defattr(-,root,root,-)
%doc license.txt readme.txt
%ghost %{_bindir}/unrar
%{_bindir}/unrar-nonfree
%{_mandir}/man1/unrar-nonfree.1*

%files -n libunrar
%defattr(-,root,root,-)
%doc license.txt readme.txt
%{_libdir}/*.so

%files -n libunrar-devel
%defattr(-,root,root,-)
%doc license.txt readme.txt
%config %{_sysconfdir}/rpm/macros.unrar
%{_includedir}/*


%changelog
* Sat Nov 5 2022 Sami Farin <> - 6.2.1-1
- Update to 6.2.1
