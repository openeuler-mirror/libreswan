%global libreswan_config \\\
    FINALMANDIR=%{_mandir} \\\
    INC_USRLOCAL=%{_prefix} \\\
    INC_RCDEFAULT=%{_initrddir} \\\
    FINALLIBEXECDIR=%{_libexecdir}/ipsec \\\
    FIPSPRODUCTCHECK=%{_sysconfdir}/system-fips \\\
    INITSYSTEM=systemd \\\
    NSS_REQ_AVA_COPY=false \\\
    USE_DNSSEC=true \\\
    USE_FIPSCHECK=true \\\
    USE_LABELED_IPSEC=true \\\
    USE_LDAP=true \\\
    USE_LIBCAP_NG=true \\\
    USE_LIBCURL=true \\\
    USE_LINUX_AUDIT=true \\\
    USE_NM=true \\\
    USE_SECCOMP=true \\\
    USE_XAUTHPAM=true \\\
%{nil}

Name:             libreswan
Version:          3.25
Release:          10
Summary:          A free implementation of IPsec & IKE for Linux
License:          GPLv2
Url:              https://github.com/libreswan/libreswan
Source0:          https://github.com/libreswan/libreswan/archive/v%{version}.tar.gz
Source1:          openeuler-libreswan-sysctl.conf
Source2:          openeuler-libreswan-tmpfiles.conf

Patch0001:        libreswan-3.25-relax-delete.patch
Patch0002:        libreswan-3.25-unbound-hook.patch
Patch0003:        0001-Replace-and-remove-deprecated-libselinux-functions.patch
Patch0004:        0002-fixup-last-two-occurances-of-security_context_t.patch
Patch0005:        0003-fix-pluto-abort.patch

BuildRequires:    gcc pkgconfig hostname bison flex systemd-devel nss-devel >= 3.16.1
BuildRequires:    nspr-devel pam-devel libevent-devel unbound-devel >= 1.6.0-6 ldns-devel
BuildRequires:    libseccomp-devel libselinux-devel fipscheck-devel audit-libs-devel
BuildRequires:    libcap-ng-devel openldap-devel curl-devel xmlto

Requires:         fipscheck nss-tools nss-softokn iproute >= 2.6.8 unbound-libs >= 1.6.6
Requires:         %{name}-help = %{version}-%{release}
Requires(post):   bash coreutils systemd
Requires(preun):  systemd
Requires(postun): systemd

Provides:         openswan = %{version}-%{release} openswan-doc = %{version}-%{release}
Obsoletes:        openswan < %{version}-%{release}
Conflicts:        openswan < %{version}-%{release}

%description
Libreswan is an Internet Key Exchange (IKE) implementation for Linux.
It supports IKEv1 and IKEv2 and has support for most of the extensions
(RFC + IETF drafts) related to IPsec, including IKEv2, X.509 Digital
Certificates, NAT Traversal, and many others. Libreswan uses the native
Linux IPsec stack (NETKEY/XFRM) per default.

%package help
Summary:          Help documents for libreswan
Requires:         %{name} = %{version}-%{release}

%description help
Man pages and other related help documents for libreswan.

%prep
%autosetup -n %{name}-%{version} -p1
sed -i "s:/usr/bin/python:/usr/bin/python3:" programs/show/show.in
sed -i "s:/usr/bin/python:/usr/bin/python3:" programs/verify/verify.in
sed -i "s:/usr/bin/python:/usr/bin/python3:" testing/x509/dist_certs.py
sed -i "s:/usr/bin/python:/usr/bin/python3:" testing/cert_verify/usage_test
sed -i "s:/usr/bin/python:/usr/bin/python3:" testing/pluto/ikev1-01-fuzzer/cve-2015-3204.py
sed -i "s:/usr/bin/python:/usr/bin/python3:" testing/pluto/ikev2-15-fuzzer/send_bad_packets.py
sed -i "s:#[ ]*include \(.*\)\(/crypto-policies/back-ends/libreswan.config\)$:include \1\2:" programs/configs/ipsec.conf.in

%build
%make_build \
    USERCOMPILE="-g -DGCC_LINT %{optflags} %{?efence} -fPIE -pie -fno-strict-aliasing -Wformat-nonliteral -Wformat-security" \
    USERLINK="-g -pie -Wl,-z,relro,-z,now %{?efence}" %{libreswan_config} programs
FS=$(pwd)

%define __spec_install_post \
    %{?__debug_package:%{__debug_install_post}} \
    %{__arch_install_post} \
    %{__os_install_post} \
    fipshmac -d %{buildroot}%{_libdir}/fipscheck %{buildroot}%{_libexecdir}/ipsec/pluto \
%{nil}

%install
%make_install %{libreswan_config}
FS=$(pwd)

install -d -m 0700 %{buildroot}{%{_rundir}/pluto,%{_localstatedir}/log/pluto/peer}
install -d %{buildroot}{%{_sbindir},%{_tmpfilesdir},%{_libdir}/fipscheck,%{_sysconfdir}/sysctl.d}

install -m 0644 %{SOURCE1} %{buildroot}%{_sysconfdir}/sysctl.d/50-libreswan.conf

install -m 0644 %{SOURCE2} %{buildroot}%{_tmpfilesdir}/libreswan.conf

echo "include %{_sysconfdir}/ipsec.d/*.secrets" > %{buildroot}%{_sysconfdir}/ipsec.secrets

%check

export NSS_DISABLE_HW_GCM=1

%post
%systemd_post ipsec.service

%preun
%systemd_preun ipsec.service

%postun
%systemd_postun_with_restart ipsec.service

%files
%doc COPYING CREDITS
%{_sbindir}/ipsec
%{_libexecdir}/ipsec
%{_libdir}/fipscheck/pluto.hmac
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/ipsec.secrets
%attr(0644,root,root) %{_unitdir}/ipsec.service
%attr(0644,root,root) %{_tmpfilesdir}/libreswan.conf
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.d/policies/*
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/sysctl.d/50-libreswan.conf
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/{ipsec.conf,pam.d/pluto}
%attr(0700,root,root) %dir %{_sysconfdir}/{ipsec.d,ipsec.d/policies}
%attr(0700,root,root) %dir %{_localstatedir}/log/{pluto,pluto/peer}
%attr(0755,root,root) %dir %{_rundir}/pluto
%exclude /usr/share/doc/libreswan
%exclude %{_sysconfdir}/rc.d/rc*

%files help
%doc README* CHANGES docs/*.* docs/examples
%doc %{_mandir}/*/*

%changelog
* Thu Nov 26 2020 lingsheng <lingsheng@huawei.com> - 3.25-10
- Fix pluto abrt

* Thu Nov 05 2020 Ge Wang <wangge20@huawei.com> - 3.25-9
- Set help package as libreswan package's install require

* Tue Sep 22 2020 huanghaitao <huanghaitao8@huawei.com> - 3.25-8
- Fix libselinux deprecates

* Mon Sep 14 2020 Ge Wang <wangge20@huawei.com> - 3.25-7
- Modify Source0 Url

* Fri Apr 03 2020 Jiangping Hu <hujp1985@foxmail.com> - 3.25-6
- Add config files

* Mon Oct 28 2019 yanzhihua <yanzhihua4@huawei.com> - 3.25-4
- Package init

