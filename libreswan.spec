%global nss_version 3.44.0-8
%global unbound_version 1.6.6
%global libreswan_config \\\
    SHELL_BINARY=/usr/bin/sh \\\
    FINALLIBEXECDIR=%{_libexecdir}/ipsec \\\
    FINALMANDIR=%{_mandir} \\\
    PREFIX=%{_prefix} \\\
    INITSYSTEM=systemd \\\
    NSS_REQ_AVA_COPY=false \\\
    NSS_HAS_IPSEC_PROFILE=true \\\
    PYTHON_BINARY=%{__python3} \\\
    USE_DNSSEC=true \\\
    USE_FIPSCHECK=false \\\
    USE_LABELED_IPSEC=true \\\
    USE_LDAP=true \\\
    USE_LIBCAP_NG=true \\\
    USE_LIBCURL=true \\\
    USE_LINUX_AUDIT=true \\\
    USE_NM=true \\\
    USE_SECCOMP=true \\\
    USE_AUTHPAM=true \\\
    USE_NSS_KDF=true \\\
%{nil}


Name: libreswan
Summary: IKE implementation for IPsec with IKEv1 and IKEv2 support
Version: 4.5
Release: 1
License: GPLv2
Url: https://libreswan.org/
Source0: https://download.libreswan.org/%{name}-%{version}.tar.gz
Source1: https://download.libreswan.org/cavs/ikev1_dsa.fax.bz2
Source2: https://download.libreswan.org/cavs/ikev1_psk.fax.bz2
Source3: https://download.libreswan.org/cavs/ikev2.fax.bz2
Source4: openeuler-libreswan-sysctl.conf


BuildRequires: audit-libs-devel
BuildRequires: bison
BuildRequires: curl-devel
BuildRequires: flex
BuildRequires: gcc make
BuildRequires: ldns-devel
BuildRequires: libcap-ng-devel
BuildRequires: libevent-devel
BuildRequires: libseccomp-devel
BuildRequires: libselinux-devel
BuildRequires: nspr-devel
BuildRequires: nss-devel >= %{nss_version}
BuildRequires: nss-tools
BuildRequires: openldap-devel
BuildRequires: pam-devel
BuildRequires: pkgconfig
BuildRequires: hostname
BuildRequires: systemd-devel
BuildRequires: unbound-devel >= %{unbound_version}
BuildRequires: xmlto

Requires: %{name}-help = %{version}-%{release}
Requires: iproute >= 2.6.8
Requires: nss >= %{nss_version}
Requires: nss-softokn
Requires: nss-tools
Requires: unbound-libs >= %{unbound_version}
Requires(post): bash
Requires(post): coreutils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
Libreswan is an implementation of IKEv1 and IKEv2 for IPsec. IPsec is
the Internet Protocol Security and uses strong cryptography to provide
both authentication and encryption services.  These services allow you
to build secure tunnels through untrusted networks.  Everything passing
through the untrusted net is encrypted by the ipsec gateway machine and
decrypted by the gateway at the other end of the tunnel.  The resulting
tunnel is a virtual private network or VPN.

This package contains the daemons and userland tools for setting up
Libreswan.

Libreswan also supports IKEv2 (RFC7296) and Secure Labeling

Libreswan is based on Openswan-2.6.38 which in turn is based on FreeS/WAN-2.04

%package help
Summary:    Help documents for libreswan

%description help
Man pages and other related help documents for libreswan.

%prep
%setup -q -n libreswan-%{version}%{?prever}

sed -i "s/-lfreebl //" mk/config.mk

sed -i "s:#[ ]*include \(.*\)\(/crypto-policies/back-ends/libreswan.config\)$:include \1\2:" configs/ipsec.conf.in

sed -i "s/-pthread$/-DALLOW_MICROSOFT_BAD_PROPOSAL -pthread/" mk/config.mk

sed -i '/config setup/a\\t# Specifies a directory forNSS database files\n\tnssdir=/etc/ipsec.d' configs/ipsec.conf.in

sed -i '/ipsec --checknss/s/$/ --nssdir \/etc\/ipsec.d/' ./initsystems/systemd/ipsec.service.in

%build
make %{?_smp_mflags} \
    OPTIMIZE_CFLAGS="%{optflags}" \
    WERROR_CFLAGS="-Werror -Wno-missing-field-initializers -Wno-lto-type-mismatch -Wno-maybe-uninitialized" \
    USERLINK="-Wl,-z,relro -Wl,--as-needed  -Wl,-z,now -flto --no-lto" \
    %{libreswan_config} \
    programs
FS=$(pwd)

%install
make \
  DESTDIR=%{buildroot} \
  %{libreswan_config} \
  install
FS=$(pwd)
rm -rf %{buildroot}/usr/share/doc/libreswan
rm -rf %{buildroot}%{_libexecdir}/ipsec/*check

install -d -m 0755 %{buildroot}%{_rundir}/pluto
install -d %{buildroot}%{_sbindir}

install -d %{buildroot}%{_sysconfdir}/sysctl.d
install -m 0644 %{SOURCE4} \
  %{buildroot}%{_sysconfdir}/sysctl.d/50-libreswan.conf

echo "include %{_sysconfdir}/ipsec.d/*.secrets" \
     > %{buildroot}%{_sysconfdir}/ipsec.secrets
rm -fr %{buildroot}%{_sysconfdir}/rc.d/rc*

%check
cp %{SOURCE1} %{SOURCE2} %{SOURCE3} .
bunzip2 *.fax.bz2

: starting CAVS test for IKEv2
%{buildroot}%{_libexecdir}/ipsec/cavp -v2 ikev2.fax | \
    diff -u ikev2.fax - > /dev/null
: starting CAVS test for IKEv1 RSASIG
%{buildroot}%{_libexecdir}/ipsec/cavp -v1dsa ikev1_dsa.fax | \
    diff -u ikev1_dsa.fax - > /dev/null
: starting CAVS test for IKEv1 PSK
%{buildroot}%{_libexecdir}/ipsec/cavp -v1psk ikev1_psk.fax | \
    diff -u ikev1_psk.fax - > /dev/null
: CAVS tests passed

%{buildroot}%{_libexecdir}/ipsec/algparse -tp || { echo prooposal test failed; exit 1; }
%{buildroot}%{_libexecdir}/ipsec/algparse -ta || { echo algorithm test failed; exit 1; }

tmpdir=$(mktemp -d /tmp/libreswan-XXXXX)
certutil -N -d sql:$tmpdir --empty-password
%{buildroot}%{_libexecdir}/ipsec/pluto --selftest --nssdir $tmpdir --rundir $tmpdir
: pluto self-test passed - verify FIPS algorithms allowed is still compliant with NIST


%post
%systemd_post ipsec.service

%preun
%systemd_preun ipsec.service

%postun
%systemd_postun_with_restart ipsec.service

%files
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.conf
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/ipsec.secrets
%attr(0700,root,root) %dir %{_sysconfdir}/ipsec.d
%attr(0700,root,root) %dir %{_sysconfdir}/ipsec.d/policies
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.d/policies/*
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/sysctl.d/50-libreswan.conf
%attr(0755,root,root) %dir %{_rundir}/pluto
%attr(0644,root,root) %{_tmpfilesdir}/libreswan.conf
%attr(0644,root,root) %{_unitdir}/ipsec.service
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/pam.d/pluto
%attr(0700,root,root) %dir %{_sharedstatedir}/ipsec/nss
%config(noreplace) %{_sysconfdir}/logrotate.d/libreswan
%{_sbindir}/ipsec
%{_libexecdir}/ipsec

%files help
%doc CHANGES COPYING CREDITS README* LICENSE
%doc docs/*.* docs/examples
%attr(0644,root,root) %doc %{_mandir}/*/*

%changelog
* Mon Apr 18 2022 yangping <yangping69@h-partners.com> - 4.5-1
- Update to 4.5

* Wed Aug 11 2021 caodongxia <caodongxia@huawei.com> - 4.1-2
- Fix algparse unknown option -d

* Fri Dec 04 2020 lingsheng <lingsheng@huawei.com> - 4.1-1
- Update to 4.1

* Tue Sep 15 2020 Guoshuai Sun <sunguoshuai@huawei.com> - 3.25-10
- Fix pluto abort

* Tue Sep 15 2020 Guoshuai Sun <sunguoshuai@huawei.com> - 3.25-9
- Fix libselinux deprecated instead of ignore the Werror

* Mon Sep 14 2020 Ge Wang <wangge20@huawei.com> - 3.25-8
- Modify Source0 Url

* Tue Aug 04 2020 zhangjiapeng <zhangjiapeng9@huawei.com> - 3.25-7
- Workaround deprecation warnings introduced in update libselinux >= 3.1

* Fri Apr 03 2020 Jiangping Hu <hujp1985@foxmail.com> - 3.25-6
- Add config files

* Mon Oct 28 2019 yanzhihua <yanzhihua4@huawei.com> - 3.25-4
- Package init

