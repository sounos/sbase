# Authority: SounOS.org

Summary: Server Base Library for TCP/UDP communication
Name: libsbase
Version: 1.0.6
Release: 3%{?dist}
License: BSD
Group: System Environment/Libraries
URL: http://code.google.com/p/sbase/

Source: http://code.google.com/p/sbase/download/%{name}-%{version}.tar.gz
Packager: SounOS <SounOS@gmail.com>
Vendor: SounOS
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

BuildRequires: libevbase >= 0.0.18
Requires: libevbase >= 0.0.18

%description
Server Base Library for TCP/UDP communication

%prep
%setup

%build
%configure
%{__make}

%install
%{__rm} -rf %{buildroot}
%{__make} install DESTDIR="%{buildroot}"

%clean
%{__rm} -rf %{buildroot}

%post

/sbin/ldconfig
/usr/sbin/useradd -M -s /sbin/nologin xhttpd
/sbin/chkconfig --add xhttpd && /sbin/chkconfig --level 345 xhttpd on

%preun

[ "`pstree|grep xhttpd|wc -l`" -gt "0" ] && /sbin/service xhttpd stop
/sbin/chkconfig --del xhttpd
/usr/sbin/userdel xhttpd

%files
%defattr(-, root, root, 0755)
%{_includedir}/*
%{_bindir}/*
%{_sbindir}/*
%{_libdir}/*
%{_sysconfdir}/rc.d/*
%config(noreplace) %{_sysconfdir}/*.ini

%changelog
* Tue Mar 09 2010 14:48:22 CST SounOS <SounOS@gmail.com>
- added service->newchunk() conn->send_chunk();
- updated procthread->run();

* Wed Jun 27 2007 14:19:04 CST SounOS <SounOS@gmail.com>
- Fixed terminate_session result program crash bug , replaced it with  MESSAGE_QUIT

* Wed Jun 20 2007 10:00:53 CST SounOS <SounOS@gmail.com>
- Updated source code version to 0.1.6
- Fixed recv OOB and Terminate Connection bug
- Update thread->clean service->clean session->clean
- Fixed ev_init() evbase_init() to clean memory leak bug
