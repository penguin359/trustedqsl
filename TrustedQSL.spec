Summary: TrustedQSL ham-radio applications
Name: TrustedQSL
Version: 1.11
Release: 1
Copyright: Custom BSD-like
Group: Applications/Ham Radio
Source: %{name}-%{version}.tar.gz
BuildRoot: /var/tmp/%{name}-buildroot
Requires: tqsllib >= 1.2, wxwin
BuildPrereq: tqsllib-devel

%description
The TrustedQSL applications are used for generating digitally signed
QSO records (records of Amateur Radio contacts). This package
contains the GUI applications tqslcert and tqsl.

%prep
%setup -q -n TrustedQSL-%{version}

%build
./configure --prefix=/usr ${TQSL_CONFIG_OPTS}
make

%install
rm -rf $RPM_BUILD_ROOT
make DESTDIR=$RPM_BUILD_ROOT install-strip
mkdir -p $RPM_BUILD_ROOT/usr/share/applications
cp tqsl.desktop $RPM_BUILD_ROOT/usr/share/applications/TrustedQSL-tqsl.desktop
cp tqslcert.desktop $RPM_BUILD_ROOT/usr/share/applications/TrustedQSL-tqslcert.desktop
mkdir -p $RPM_BUILD_ROOT/usr/share/pixmaps
cp icons/key48.png $RPM_BUILD_ROOT/usr/share/pixmaps/TrustedQSL.png

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc LICENSE

/usr/bin/tqsl
/usr/bin/tqslcert
/usr/share/TrustedQSL/help/tqslcert
/usr/share/TrustedQSL/help/tqslapp
/usr/share/applications/TrustedQSL-tqsl.desktop
/usr/share/applications/TrustedQSL-tqslcert.desktop
/usr/share/pixmaps/TrustedQSL.png
