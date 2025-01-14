# A simplified kernel spec initially based on Tencent Linux Kernels and Fedora/CentOS
#
# By changing a few rpm macros, it's very convenient to build for different archs or
# kernel config styles, and build different components.
### Kenrel version relation macros
# Following variables filled by automation scripts:
# %%{kernel_majver}: Kernel RPM package version, eg. 5.15.0, 5.15.3, 5.16.0
# %%{kernel_relver}: Kernel RPM package release, eg. 2207.1, 0.20211115git1135ec008ef3.rc0.2207, 0009.11
# %%{kernel_variant}: Kernel RPM package release, eg. 2207.1, 0.20211115git1135ec008ef3.rc0.2207, 0009.11
# %%{kernel_tarname} Kernel Source tar's basename and prefix after untar, eg. 5.16.0.20211115git1135ec008ef3.rc0.2207
# %%{kernel_unamer}: Define `uname -r` output, needed by scriptlets so prepare it early. (KVER.%{{?dist}}.%{{_target_cpu}}%{{kernel_variant}})
# %%{rpm_name}: Kernel RPM package name, eg. kernel, kernel-tlinux4, kernel-stream kernel-stream-debug
# %%{rpm_vendor}: RPM package vendor
# %%{rpm_url}: RPM url
# TODO: kernel_unamer don't have distro mark
{{VERSIONSPEC}}

# This section defines following value:
# %%{kernel_arch}
# Since kernel arch name differs from many other definations, this will insert a script snip
# to handle the convertion, and error out on unsupported arch.
{{ARCHSPEC}}

# TODO: This is a workaround for kernel userspace tools (eg. perf), which doesn't
# support LTO, and causes FTBFS, need to remove this after LTO is available in
# upstream
%global _lto_cflags %{nil}

###### Kernel packaging options #################################################
# Since we need to generate kernel, kernel-subpackages, perf, bpftools, from
# this one single code tree, following build switches are very helpful.
#
# The following build options can be enabled or disabled with --with/--without
# in the rpmbuild command. But may by disabled by later checks#
#
# This section defines following options:
# with_core: kernel core pkg
# with_doc: kernel doc pkg
# with_headers: kernel headers pkg
# with_perf: perf tools pkg
# with_tools: kernel tools pkg
# with_bpftool: bpftool pkg
# with_debuginfo: debuginfo for all packages
# with_modsign: if mod should be signed
# with_kabichk: if kabi check is needed at the end of build
# with_keypkg: package the signing key for user, CAUTION: this package allows
#              users to be able to sign their modules using kernel trusted key.
{{PKGPARAMSPEC}}

# Only use with cross build, don't touch it unless you know what you are doing
%define with_crossbuild	%{?_with_crossbuild: 1}		%{?!_with_crossbuild: 0}

###### Kernel signing params #################################################
### TODO: Currently only module signing, no secureboot
# module-keygen
# Should be an executable accepting two params:
# module-keygen <kernel ver> <kernel objdir>
# <kernel ver>: Kernel's version-release, `uname -r` output of that kernel
# <kernel objdir>: Kernel build dir, where built kernel objs, certs, and vmlinux is stored
#
# This executable should provide required keys for signing, or at least disable builtin keygen
%define use_builtin_module_keygen %{?_module_keygen: 0} %{?!_module_keygen: 1}

# module-signer
# Should be an executable accepting three params:
# module-signer <buildroot> <kernel ver> <kernel objdir>
# <kernel ver>: Kernel's version-release, `uname -r` output of that kernel
# <kernel objdir>: Kernel build dir, where built kernel objs, certs, and vmlinux is stored
# <buildroot>: RPM's buildroot, where kernel modules are installed into
#
# This executable should sign all kernel modules in <builddir>/lib/modules/<kernel ver>
# based on the info gatherable from <kernel objdir>.
%define use_builtin_module_signer %{?_module_signer: 0} %{?!_module_signer: 1}

###### Required RPM macros #####################################################

### Debuginfo handling
# Following macros controls RPM's builtin debuginfo extracting behaviour,
# tune it into a kernel friendly style.
#
# Kernel package needs its own method to pack the debuginfo files.
# This disables RPM's built-in debuginfo files packaging, we package
# debuginfo files manually use find-debuginfo.sh.
%undefine _debuginfo_subpackages
# This disables RH vendor macro's debuginfo package template generation.
# It only generates debuginfo for the main package, but we only want debuginfo
# for subpackages so disable it and do things manually.
%undefine _enable_debug_packages
# This disable find-debuginfo.sh from appending minimal debuginfo
# to every binary.
%undefine _include_minidebuginfo
# This disables debugsource package which collect source files for debug info,
# we pack the kernel source code manually.
%undefine _debugsource_packages
# TODO: This prevents find-debuginfo.sh from adding unique suffix to .ko.debug files
# that will make .ko.debug file names unrecognizable by `crash`
# We may patch `crash` to fix that or find a better way, since this stops the unique
# debug file renaming for userspace packages too.
%undefine _unique_debug_names
# Pass --reloc-debug-sections to eu-strip, .ko files are ET_REL files. So they have relocation
# sections for debug sections. Those sections will not be relinked. This help create .debug files
# that has cross debug section relocations resolved.
%global _find_debuginfo_opts -r
%global debuginfo_dir /usr/lib/debug

###### Build time config #######################################################
# Disable kernel building for non-supported arch, allow building userspace package
%ifarch %nobuildarches noarch
%global with_core 0
%endif

# Require cross compiler if cross compiling
%if %{with_crossbuild}
BuildRequires: binutils-%{_build_arch}-linux-gnu, gcc-%{_build_arch}-linux-gnu
%global with_perf 0
%global with_tools 0
%global with_bpftool 0
%global _cross_compile %{!?_cross_compile:%{_build_arch}-linux-gnu-}%{?_cross_compile:%{_cross_compile}}
%endif

# List the packages used during the kernel build
BuildRequires: kmod, patch, bash, coreutils, tar, git-core, which, gawk
BuildRequires: make, gcc, binutils, system-rpm-config, hmaccalc, bison, flex, gcc-c++
BuildRequires: bzip2, xz, findutils, gzip, perl-interpreter, perl-Carp, perl-devel
BuildRequires: net-tools, hostname, bc
BuildRequires: dwarves
BuildRequires: openssl-devel, elfutils-devel
# Required by multiple kernel tools
BuildRequires: python3-devel, python3-setuptools
BuildRequires: openssl
BuildRequires: gcc-plugin-devel
# glibc-static is required for a consistent build environment (specifically
# CONFIG_CC_CAN_LINK_STATIC=y).
BuildRequires: glibc-static
# Kernel could be compressed with lz4
BuildRequires: lz4
# Needing clone sub git repo
BuildRequires: git

%if %{with_perf}
BuildRequires: zlib-devel binutils-devel newt-devel perl(ExtUtils::Embed) bison flex xz-devel
BuildRequires: audit-libs-devel
BuildRequires: java-devel
BuildRequires: libbabeltrace-devel
BuildRequires: libtraceevent-devel
%ifnarch aarch64
BuildRequires: numactl-devel
%endif
%endif

%if %{with_tools}
BuildRequires: gettext ncurses-devel
BuildRequires: pciutils-devel libcap-devel libnl3-devel libtool
%endif

%if %{with_doc}
BuildRequires: xmlto, asciidoc
%endif

%if %{with_bpftool}
BuildRequires: llvm
# We don't care about this utils's python version, since we only want rst2* commands during build time
BuildRequires: /usr/bin/rst2man
BuildRequires: zlib-devel binutils-devel
%endif

%if %{with_headers}
BuildRequires: rsync
%endif

###### Kernel packages sources #################################################
### Kernel tarball
Source0: %{kernel_tarname}.tar.gz

### Build time scripts
# Script used to assist kernel building
Source10: filter-modules.sh

Source20: module-signer.sh
Source21: module-keygen.sh

Source30: check-kabi

# RUE module load at boot
Source40: rue.conf

### Arch speficied kernel configs and kABI
# Start from Source1000 to Source1199, for kernel config
# Start from Source1200 to Source1399, for kabi
{{ARCHSOURCESPEC}}

### Userspace tools
# Start from Source2000 to Source2999, for userspace tools
Source2000: cpupower.service
Source2001: cpupower.config

### Used for download thirdparty drivers
# Start from Source3000 to Source3099, for thirdparty release drivers
Source3000: download-and-copy-drivers.sh
Source3001: MLNX_OFED_LINUX-23.10-3.2.2.0-rhel9.4-x86_64.tgz
Source3002: install.sh

###### Kernel package definations ##############################################
### Main meta package
Summary: %{rpm_vendor} Linux kernel meta package
Name: %{rpm_name}
Version: %{kernel_majver}
Release: %{kernel_relver}%{?dist}
License: GPLv2
URL: %{rpm_url}

# We can't let RPM do the dependencies automatic because it'll then pick up
# a correct but undesirable perl dependency from the module headers which
# isn't required for the kernel proper to function
AutoReq: no
AutoProv: yes

# Kernel requirements
# installonlypkg(kernel) is a hint for RPM that this package shouldn't be auto-cleaned.
Provides: installonlypkg(kernel)
Provides: kernel = %{version}-%{release}
Provides: %{rpm_name} = %{version}-%{release}
Requires: %{rpm_name}-core = %{version}-%{release}
Requires: %{rpm_name}-modules = %{version}-%{release}
Requires: linux-firmware

%description
This is the meta package of %{?rpm_vendor:%{rpm_vendor} }Linux kernel, the core of operating system.

%if %{with_core}
### Kernel core package
%package core
Summary: %{rpm_vendor} Linux Kernel
Provides: installonlypkg(kernel)
Provides: kernel = %{version}-%{release}
Provides: %{rpm_name}-core = %{version}-%{release}
Provides: %{rpm_name}-core-uname-r = %{kernel_unamer}
Provides: kernel-uname-r = %{kernel_unamer}
Requires(pre): coreutils
Requires(post): coreutils kmod dracut
Requires(preun): coreutils kmod
Requires(post): %{_bindir}/kernel-install
Requires(preun): %{_bindir}/kernel-install
# Kernel install hooks & initramfs
%if 0%{?rhel} == 7 || "%{?dist}" == ".tl2"
Requires(post): systemd
Requires(preun): systemd
%else
Requires(post): systemd-udev
Requires(preun): systemd-udev
%endif

%description core
The kernel package contains the %{?rpm_vendor:%{rpm_vendor} } Linux kernel (vmlinuz), the core of
operating system. The kernel handles the basic functions
of the operating system: memory allocation, process allocation, device
input and output, etc.

### Kernel module package
%package modules
Summary: %{rpm_vendor} Kernel modules to match the %{rpm_name}-core kernel
Provides: installonlypkg(kernel-module)
Provides: %{rpm_name}-modules = %{version}-%{release}
Provides: %{rpm_name}-modules-uname-r = %{kernel_unamer}
Provides: kernel-modules = %{kernel_unamer}
Provides: kernel-modules-extra = %{version}-%{release}
Requires: %{rpm_name}-core = %{version}-%{release}
AutoReq: no
AutoProv: yes
Requires(pre): kmod
Requires(postun): kmod
%description modules
This package provides commonly used kernel modules for the %{?2:%{2}-}core kernel package.

### Kernel devel package
%package devel
Summary: Development package for building kernel modules to match the %{version}-%{release} kernel
Release: %{release}
Provides: installonlypkg(kernel)
Provides: %{rpm_name}-devel = %{version}-%{release}
Provides: %{rpm_name}-devel-%{_target_cpu} = %{version}-%{release}
Provides: kernel-devel-uname-r = %{kernel_unamer}
AutoReqprov: no
%description devel
This package provides kernel headers and makefiles sufficient to build modules
against the %{version}-%{release} kernel package.

### Kernel module package
%if %{with_keypkg}
%package signing-keys
Summary: %{rpm_vendor} Kernel signing key
Provides: installonlypkg(kernel)
Requires: %{rpm_name}-core = %{version}-%{release}
AutoReq: no
AutoProv: yes
%description signing-keys
This package provides kernel signing key for the %{?2:%{2}-}core kernel package.
%endif

%if %{with_debuginfo}
### Kernel debuginfo package
%package debuginfo
Summary: Debug information for package %{rpm_name}
# TK: Break the chain of dependency, to allow independent distribution of debuginfo/debuginfo-common
# debuginfo-common contains source code, and because of how `crash` utility works, it's included in
# this -common package instead of standalone debugsource (which is usually distributed in standlone
# repo, and causes trouble for uses)
# Removed "Requires: kernel--debuginfo-common = xxx"
# More info, pls run "git blame dist/templates/kernel.template.spec" (or "git log -p dist/templates/kernel.template.spec")
# to find and read the relevant commit.
Provides: installonlypkg(kernel)
Provides: %{rpm_name}-debuginfo = %{version}-%{release}
AutoReqProv: no
%description debuginfo
This package provides debug information including
vmlinux, System.map for package %{rpm_name}.
This is required to use SystemTap with %{rpm_name}.
# debuginfo search rule
# If BTF presents, keep it so kernel can use it.
%if 0%{?rhel} != 7
# Old version of find-debuginfo.sh doesn't support this, so only do it for newer version. Old version of eu-strip seems doesn't strip BTF either, so should be fine.
%global _find_debuginfo_opts %{_find_debuginfo_opts} --keep-section '.BTF'
%endif
# Debuginfo file list for main kernel package
# The (\+.*)? is used to match all variant kernel
%global _find_debuginfo_opts %{_find_debuginfo_opts} -p '.*\/usr\/src\/kernels/.*|XXX' -o ignored-debuginfo.list -p $(echo '.*/%{kernel_unamer}/.*|.*/%{kernel_unamer}(\.debug)?' | sed 's/+/[+]/g') -o debuginfo.list
# with_debuginfo
%endif
# with_core
%endif

%if %{with_debuginfo}
### Common debuginfo package
%package debuginfo-common
Summary: Kernel source files used by %{rpm_name}-debuginfo packages
Provides: installonlypkg(kernel)
Provides: %{rpm_name}-debuginfo-common = %{version}-%{release}
%description debuginfo-common
This package is required by %{rpm_name}-debuginfo subpackages.
It provides the kernel source files common to all builds.
# No need to define extra debuginfo search rule here, use debugfiles.list
# with_debuginfo
%endif

%if %{with_headers}
%package headers
Summary: Header files for the Linux kernel for use by glibc
Obsoletes: glibc-kernheaders < 3.0-46
Provides: glibc-kernheaders = 3.0-46
Provides: kernel-headers = %{version}-%{release}
%description headers
Kernel-headers includes the C header files that specify the interface
between the Linux kernel and userspace libraries and programs. The
header files define structures and constants that are needed for
building most standard programs and are also needed for rebuilding the
glibc package.
# with_headers
%endif

%if %{with_perf}
%package -n perf
Summary: Performance monitoring for the Linux kernel
Requires: bzip2
License: GPLv2
%description -n perf
This package contains the perf tool, which enables performance monitoring
of the Linux kernel.

%package -n perf-debuginfo
Summary: Debug information for package perf
# TK: Break the chain of dependency, removed "Requires: kernel--debuginfo-common = xxx"
# More info, pls run "git blame dist/templates/kernel.template.spec" to find and read the relevant commit.
AutoReqProv: no
%description -n perf-debuginfo
This package provides debug information for the perf package.
# debuginfo search rule
# Note that this pattern only works right to match the .build-id
# symlinks because of the trailing nonmatching alternation and
# the leading .*, because of find-debuginfo.sh's buggy handling
# of matching the pattern against the symlinks file.
%global _find_debuginfo_opts %{_find_debuginfo_opts} -p '.*%{_bindir}/perf(.*\.debug)?|.*%{_libexecdir}/perf-core/.*|.*%{_libdir}/libperf-jvmti.so(.*\.debug)?|.*%{_libdir}/traceevent/(.*\.debug)?|XXX' -o perf-debuginfo.list

%package -n python3-perf
Summary: Python bindings for apps which will manipulate perf events
%description -n python3-perf
The python3-perf package contains a module that permits applications
written in the Python programming language to use the interface
to manipulate perf events.

%package -n python3-perf-debuginfo
Summary: Debug information for package perf python bindings
# TK: Break the chain of dependency, removed "Requires: kernel--debuginfo-common = xxx"
# More info, pls run "git blame dist/templates/kernel.template.spec" to find and read the relevant commit.
AutoReqProv: no
%description -n python3-perf-debuginfo
This package provides debug information for the perf python bindings.
# debuginfo search rule
# the python_sitearch macro should already be defined from above
%global _find_debuginfo_opts %{_find_debuginfo_opts} -p '.*%{python3_sitearch}/perf.*\.so(.*\.debug)?|XXX' -o python3-perf-debuginfo.list
# with_perf
%endif

%if %{with_tools}
%package -n kernel-tools
Summary: Assortment of tools for the Linux kernel
License: GPLv2
%ifarch %{cpupowerarchs}
Provides: cpupowerutils = 1:009-0.6.p1
Obsoletes: cpupowerutils < 1:009-0.6.p1
Provides: cpufreq-utils = 1:009-0.6.p1
Provides: cpufrequtils = 1:009-0.6.p1
Obsoletes: cpufreq-utils < 1:009-0.6.p1
Obsoletes: cpufrequtils < 1:009-0.6.p1
Obsoletes: cpuspeed < 1:1.5-16
Requires: kernel-tools-libs = %{version}-%{release}
%endif
%description -n kernel-tools
This package contains the tools/ directory from the kernel source
and the supporting documentation.

%package -n kernel-tools-libs
Summary: Libraries for the kernels-tools
License: GPLv2
%description -n kernel-tools-libs
This package contains the libraries built from the tools/ directory
from the kernel source.

%package -n kernel-tools-libs-devel
Summary: Assortment of tools for the Linux kernel
License: GPLv2
Requires: kernel-tools = %{version}-%{release}
%ifarch %{cpupowerarchs}
Provides: cpupowerutils-devel = 1:009-0.6.p1
Obsoletes: cpupowerutils-devel < 1:009-0.6.p1
%endif
Requires: kernel-tools-libs = %{version}-%{release}
Provides: kernel-tools-devel
%description -n kernel-tools-libs-devel
This package contains the development files for the tools/ directory from
the kernel source.

%package -n kernel-tools-debuginfo
Summary: Debug information for package kernel-tools
# TK: Break the chain of dependency, removed "Requires: kernel--debuginfo-common = xxx"
# More info, pls run "git blame dist/templates/kernel.template.spec" to find and read the relevant commit.
AutoReqProv: no
%description -n kernel-tools-debuginfo
This package provides debug information for package kernel-tools.
# debuginfo search rule
# Note that this pattern only works right to match the .build-id
# symlinks because of the trailing nonmatching alternation and
# the leading .*, because of find-debuginfo.sh's buggy handling
# of matching the pattern against the symlinks file.
%global _find_debuginfo_opts %{_find_debuginfo_opts} -p '.*%{_bindir}/(cpupower|tmon|gpio-.*|iio_.*|ls.*|centrino-decode|powernow-k8-decode|turbostat|x86_energy_perf_policy|intel-speed-select|page_owner_sort|slabinfo)(.*\.debug)?|.*%{_libdir}/libcpupower.*|XXX' -o kernel-tools-debuginfo.list
# with_tools
%endif

%if %{with_bpftool}
%package -n bpftool
Summary: Inspection and simple manipulation of eBPF programs and maps
License: GPLv2
%description -n bpftool
This package contains the bpftool, which allows inspection and simple
manipulation of eBPF programs and maps.

%package -n bpftool-debuginfo
Summary: Debug information for package bpftool
# TK: Break the chain of dependency, removed "Requires: kernel--debuginfo-common = xxx"
# More info, pls run "git blame dist/templates/kernel.template.spec" to find and read the relevant commit.
AutoReqProv: no
%description -n bpftool-debuginfo
This package provides debug information for the bpftool package.
# debuginfo search rule
%global _find_debuginfo_opts %{_find_debuginfo_opts} -p '.*%{_sbindir}/bpftool(.*\.debug)?|XXX' -o bpftool-debuginfo.list
# with_bpftool
%endif

# To avoid compile error, do not integrate mlnx commercial quality drivers if not tencentos release.
# Users could compile and install MLNX_OFED_LINUX-* manually.
#
# Some oc9 partners have nic driver, and the driver support RDMA and only compatble with kernel native infiniband.
# If integrate mlnx driver, oc9 partners RDMA nic driver cloud not run.
%if "%{?dist}" != ".tl4" && "%{?dist}" != ".tl3"
%define with_ofed 0
%endif

%if %{with_ofed}
%ifarch x86_64
%package -n mlnx-ofed-dist
Summary: Mellonax ofed rpms installation
License: GPLv2
%if "%{?dist}" != ".tl3"
## "${DISTRO}" is .tl4 or oc9
BuildRequires: kernel-srpm-macros
BuildRequires: perl-sigtrap
%endif
BuildRequires: kernel-rpm-macros
BuildRequires: lsof
BuildRequires: pciutils
%description -n mlnx-ofed-dist
This package contains all the signed ko files.
%endif
%endif

###### common macros for build and install #####################################
### Signing scripts
# If externel module signer and keygen provided, ignore built-in keygen and
# signer, else use builtin keygen and signer.
%if %{use_builtin_module_signer}
	# SOURCE20 is just a wrapper for $BUILD_DIR/scripts/sign-file
	%define _module_signer %{SOURCE20}
%endif
%if %{use_builtin_module_keygen}
	# SOURCE21 is a dummy file, only perform some checks, we depend on Kbuild for builtin keygen
	%define _module_keygen %{SOURCE21}
%endif

### Prepare common build vars to share by %%prep, %%build and %%install section
# _KernSrc: Path to kernel source, located in _buildir
# _KernBuild: Path to the built kernel objects, could be same as $_KernSrc (just like source points to build under /lib/modules/<kver>)
# _KernVmlinuxH: path to vmlinux.h for BTF, located in _buildir
# KernUnameR: Get `uname -r` output of the built kernel
# KernModule: Kernel modules install path, located in %%{buildroot}
# KernDevel: Kernel headers and sources install path, located in %%{buildroot}
%global prepare_buildvar \
	cd %{kernel_tarname} \
	_KernSrc=%{_builddir}/%{rpm_name}-%{kernel_unamer}/%{kernel_tarname} \
	_KernBuild=%{_builddir}/%{rpm_name}-%{kernel_unamer}/%{kernel_unamer}-obj \
	_KernVmlinuxH=%{_builddir}/%{rpm_name}-%{kernel_unamer}/vmlinux.h \
	KernUnameR=%{kernel_unamer} \
	KernModule=%{buildroot}/lib/modules/%{kernel_unamer} \
	KernDevel=%{buildroot}/usr/src/kernels/%{kernel_unamer} \

###### Rpmbuild Prep Stage #####################################################
%prep
%setup -q -c -n %{rpm_name}-%{kernel_unamer}
%{prepare_buildvar}

# TODO: Apply test patch here
:

# Mangle /usr/bin/python shebangs to /usr/bin/python3
# Mangle all Python shebangs to be Python 3 explicitly
# -p preserves timestamps
# -n prevents creating ~backup files
# -i specifies the interpreter for the shebang
# This fixes errors such as
# *** ERROR: ambiguous python shebang in /usr/bin/kvm_stat: #!/usr/bin/python. Change it to python3 (or python2) explicitly.
# We patch all sources below for which we got a report/error.
find scripts/ tools/ Documentation/ \
	-type f -and \( \
		-name "*.py" -or \( -not -name "*.*" -exec grep -Iq '^#!.*python' {} \; \) \
	\) \
	-exec pathfix.py -i "%{__python3} %{py3_shbang_opts}" -p -n {} \+;

# Make a copy and add suffix for kernel licence to prevent conflict of multi kernel package installation
cp $_KernSrc/COPYING $_KernSrc/COPYING.%{kernel_unamer}

# Update kernel version and suffix info to make uname consistent with RPM version
# PATCHLEVEL inconsistent only happen on first merge window, but patch them all just in case
sed -i "/^VESION/cVERSION = $(echo %{kernel_majver} | cut -d '.' -f 1)" $_KernSrc/Makefile
sed -i "/^PATCHLEVEL/cPATCHLEVEL = $(echo %{kernel_majver} | cut -d '.' -f 2)" $_KernSrc/Makefile
sed -i "/^SUBLEVEL/cSUBLEVEL = $(echo %{kernel_majver} | cut -d '.' -f 3)" $_KernSrc/Makefile

# Patch the kernel to apply uname, the reason we use EXTRAVERSION to control uname
# instead of complete use LOCALVERSION is that, we don't want out scm/rpm version info
# get inherited by random kernels built reusing the config file under /boot, which
# will be confusing.
_KVERSION=$(sed -nE "/^VERSION\s*:?=\s*(.*)/{s/^\s*^VERSION\s*:?=\s*//;h};\${x;p}" $_KernSrc/Makefile)
_KPATCHLEVEL=$(sed -nE "/^PATCHLEVEL\s*:?=\s*(.*)/{s/^\s*^PATCHLEVEL\s*:?=\s*//;h};\${x;p}" $_KernSrc/Makefile)
_KSUBLEVEL=$(sed -nE "/^SUBLEVEL\s*:?=\s*(.*)/{s/^\s*^SUBLEVEL\s*:?=\s*//;h};\${x;p}" $_KernSrc/Makefile)
_KUNAMER_PREFIX=${_KVERSION}.${_KPATCHLEVEL}.${_KSUBLEVEL}
_KEXTRAVERSION=""
_KLOCALVERSION=""

case $KernUnameR in
	$_KUNAMER_PREFIX* )
		_KEXTRAVERSION=$(echo "$KernUnameR" | sed -e "s/^$_KUNAMER_PREFIX//")

		# Anything after "+" belongs to LOCALVERSION, eg, +debug/+minimal marker.
		_KLOCALVERSION=$(echo "$_KEXTRAVERSION" | sed -ne 's/.*\([+].*\)$/\1/p')
		_KEXTRAVERSION=$(echo "$_KEXTRAVERSION" | sed -e 's/[+].*$//')

		# Update Makefile to embed uname
		sed -i "/^EXTRAVERSION/cEXTRAVERSION = $_KEXTRAVERSION" $_KernSrc/Makefile
		# Save LOCALVERSION in .dist.localversion, it will be set to .config after
		# .config is ready in BuildConfig.
		echo "$_KLOCALVERSION" > $_KernSrc/.dist.localversion
		;;
	* )
		echo "FATAL: error: kernel version doesn't match with kernel spec." >&2 && exit 1
		;;
	esac

###### Rpmbuild Build Stage ####################################################
%build

### Make flags
#
# Those defination have to be defined after %%build macro, %%build macro may change
# some build flags, and we have to inherit these changes.
#
# NOTE: kernel's tools build system doesn't playwell with command line variables, some
# `override` statement will stop working after recursive Makefile `include` call.
# So keep these variables as environment variables so they are available globally,
# `make` will transformed env vars into makefile variable in every iteration.

## Common flags
%global make %{__make} %{_smp_mflags}
%global kernel_make_opts INSTALL_HDR_PATH=%{buildroot}/usr INSTALL_MOD_PATH=%{buildroot} KERNELRELEASE=$KernUnameR
%global tools_make_opts DESTDIR="%{buildroot}" prefix=%{_prefix} lib=%{_lib} PYTHON=%{__python3} INSTALL_ROOT="%{buildroot}"

## Cross compile flags
%if %{with_crossbuild}
%global kernel_make_opts %{kernel_make_opts} CROSS_COMPILE=%{_cross_compile} ARCH=%{kernel_arch}
# make for host tool, reset arch and flags for native host bulid, also limit to 1 job for better stability
%global host_make CFLAGS= LDFLAGS= ARCH= %{make} -j1
%global __strip %{_build_arch}-linux-gnu-strip
%else
%global host_make CFLAGS= LDFLAGS= %{make} -j1
%endif

# Drop host cflags for crossbuild, arch options from build target will break host compiler
%if !%{with_crossbuild}
%global kernel_make_opts %{kernel_make_opts} HOSTCFLAGS="%{?build_cflags}" HOSTLDFLAGS="%{?build_ldflags}"
%endif

## make for kernel
%global kernel_make %{make} %{kernel_make_opts}
## make for tools
%global tools_make CFLAGS="${RPM_OPT_FLAGS}" LDFLAGS="%{__global_ldflags}" %{make} %{tools_make_opts}
%global perf_make EXTRA_CFLAGS="${RPM_OPT_FLAGS}" LDFLAGS="%{__global_ldflags}" WERROR=0 NO_LIBUNWIND=1 HAVE_CPLUS_DEMANGLE=1 NO_GTK2=1 NO_STRLCPY=1 NO_BIONIC=1 LIBTRACEEVENT_DYNAMIC=1 %{make} %{tools_make_opts}
%global bpftool_make EXTRA_CFLAGS="${RPM_OPT_FLAGS}" EXTRA_LDFLAGS="%{__global_ldflags}" %{make} %{tools_make_opts} $([ -e "$_KernVmlinuxH" ] && echo VMLINUX_H="$_KernVmlinuxH")

### Real make
%{prepare_buildvar}

# Prepare Kernel config
BuildConfig() {
	# Copy mlnx drivers to drivers/thirdparty/release-drivers/mlnx/ dir
	pushd ${_KernSrc}/drivers/thirdparty
	%if %{with_ofed}
		rm -f download-and-copy-drivers.sh; cp -a %{SOURCE3000} ./
		## Real MLNX_OFED_LINUX-*.tgz will more than 1024 bytes.
		## Dummy MLNX_OFED_LINUX-*.tgz will less than 1024 bytes.
		if [ $(stat -c%s %{SOURCE3001}) -gt 1024 ]; then
			cp -a %{SOURCE3001} release-drivers/mlnx/
			./copy-drivers.sh without_mlnx
		else
			./copy-drivers.sh
		fi
	%else
		./copy-drivers.sh without_mlnx
	%endif
	popd

	mkdir -p $_KernBuild
	pushd $_KernBuild
	cp $1 .config
	%if "%{?dist}" == ".oc9"
		cat ${_KernSrc}/kernel/configs/oc.config >> .config
	%endif

	[ "$_KernBuild" != "$_KernSrc" ] && echo "include $_KernSrc/Makefile" > Makefile
	[ "$_KernBuild" != "$_KernSrc" ] && cp $_KernSrc/.dist.localversion ./

	# Respect scripts/setlocalversion, avoid it from potentially mucking with our version numbers.
	# Also update LOCALVERSION in .config
	cp .dist.localversion .scmversion
	"$_KernSrc"/scripts/config --file .config --set-str LOCALVERSION "$(cat .dist.localversion)"

	# Ensures build-ids are unique to allow parallel debuginfo
	sed -i -e "s/^CONFIG_BUILD_SALT.*/CONFIG_BUILD_SALT=\"$KernUnameR\"/" .config

	# Call olddefconfig before make all, set all unset config to default value.
	# The packager uses CROSS_COMPILE=scripts/dummy-tools for generating .config
	# so compiler related config are always unset, let's just use defconfig for them for now
	%{kernel_make} olddefconfig

	%if %{with_modsign}
	# Don't use Kbuild's signing, use %%{_module_signer} instead, be compatible with debuginfo and compression
	sed -i -e "s/^CONFIG_MODULE_SIG_ALL=.*/# CONFIG_MODULE_SIG_ALL is not set/" .config
	%else
	# Not signing, unset all signing related configs
	sed -i -e "s/^CONFIG_MODULE_SIG_ALL=.*/# CONFIG_MODULE_SIG_ALL is not set/" .config
	sed -i -e "s/^CONFIG_MODULE_SIG_FORCE=.*/# CONFIG_MODULE_SIG_FORCE is not set/" .config
	sed -i -e "s/^CONFIG_MODULE_SIG=.*/# CONFIG_MODULE_SIG is not set/" .config
	# Lockdown can't work without module sign
	sed -i -e "s/^CONFIG_SECURITY_LOCKDOWN_LSM=.*/# CONFIG_SECURITY_LOCKDOWN_LSM is not set/" .config
	sed -i -e "s/^CONFIG_SECURITY_LOCKDOWN_LSM_EARLY=.*/# CONFIG_SECURITY_LOCKDOWN_LSM_EARLY is not set/" .config
	%endif
	# Don't use kernel's builtin module compression, imcompatible with debuginfo packaging and signing
	sed -i -e "s/^\(CONFIG_DECOMPRESS_.*\)=y/# \1 is not set/" .config
	popd
}

## $1: .config file
BuildKernel() {
	echo "*** Start building kernel $KernUnameR"
	mkdir -p $_KernBuild
	pushd $_KernBuild

	%if %{with_modsign}
	# Call keygen here, if it generate the module keys, it should come before kbuild,
	# so kbuild may avoid regenerate cert keys.
	%{_module_keygen} "$KernUnameR" "$_KernBuild"
	%endif

	# Build vmlinux
	%{kernel_make} all
	# Build modules
	grep -q "CONFIG_MODULES=y" ".config" && %{kernel_make} modules
	# CONFIG_KERNEL_HEADER_TEST generates some extra files in the process of
	# testing so just delete
	find . -name *.h.s -delete

	popd
}

BuildPerf() {
	%{perf_make} -C tools/perf all
	%{perf_make} -C tools/perf man
}

BuildTools() {
	%{tools_make} -C tools/power/cpupower CPUFREQ_BENCH=false DEBUG=false

%ifarch x86_64
	%{tools_make} -C tools/power/cpupower/debug/x86_64 centrino-decode powernow-k8-decode
	%{tools_make} -C tools/power/x86/x86_energy_perf_policy
	%{tools_make} -C tools/power/x86/turbostat
	%{tools_make} -C tools/power/x86/intel-speed-select
%endif

	%{tools_make} -C tools/thermal/tmon/
	%{tools_make} -C tools/iio/
	%{tools_make} -C tools/gpio/
	%{tools_make} -C tools/mm/ slabinfo page_owner_sort
}

BuildBpfTool() {
	echo "*** Building bootstrap bpftool and extrace vmlinux.h"
	if ! [ -s $_KernVmlinuxH ]; then
		# Precompile a minimized bpftool without vmlinux.h, use it to extract vmlinux.h
		# for bootstraping the full feature bpftool
		%{host_make} -C tools/bpf/bpftool/ VMLINUX_BTF= VMLINUX_H=
		# Prefer to extract the vmlinux.h from the vmlinux that were just compiled
		# fallback to use host's vmlinux
		# Skip this if bpftools is too old and doesn't support BTF dump
		if tools/bpf/bpftool/bpftool btf help 2>&1 | grep -q "\bdump\b"; then
			if grep -q "CONFIG_DEBUG_INFO_BTF=y" "$_KernBuild/.config" && [ -s "$_KernBuild/vmlinux" ]; then
				tools/bpf/bpftool/bpftool btf dump file "$_KernBuild/vmlinux" format c > $_KernVmlinuxH
			else
				if [ -e /sys/kernel/btf/vmlinux ]; then
					tools/bpf/bpftool/bpftool btf dump file /sys/kernel/btf/vmlinux format c > $_KernVmlinuxH
				fi
			fi
		fi
		%{host_make} -C tools/bpf/bpftool/ clean
	fi

	echo "*** Building bpftool"
	%{bpftool_make} -C tools/bpf/bpftool
}

%if %{with_core}
{{CONFBUILDSPEC}} # `BuildConfig <.config from CONFSOURCESPEC>`
BuildKernel
%endif

%if %{with_perf}
BuildPerf
%endif

%if %{with_tools}
BuildTools
%endif

%if %{with_bpftool}
BuildBpfTool
%endif

###### Rpmbuild Install Stage ##################################################
%install
%{prepare_buildvar}

InstKernelBasic() {
	####### Basic environment ##################
	# prepare and pushd into the kernel module top dir
	mkdir -p $KernModule
	pushd $KernModule

	####### modules_install ##################
	pushd $_KernBuild
	# Override $(mod-fw) because we don't want it to install any firmware
	# we'll get it from the linux-firmware package and we don't want conflicts
	grep -q "CONFIG_MODULES=y" ".config" && %{kernel_make} mod-fw= modules_install
	# Check again, don't package firmware, use linux-firmware rpm instead
	rm -rf %{buildroot}/lib/firmware
	popd

	####### Prepare kernel modules files for packaging ################
	# Don't package depmod files, they should be auto generated by depmod at rpm -i
	rm -f modules.{alias,alias.bin,builtin.alias.bin,builtin.bin} \
		modules.{dep,dep.bin,devname,softdep,symbols,symbols.bin}

	# Process kernel modules
	find . -name "*.ko" -type f | \
	while read -r _kmodule; do
		# Mark it executable so strip and find-debuginfo can see it
		chmod u+x "$_kmodule"

		# Detect missing or incorrect license tags
		modinfo "$_kmodule" -l | grep -E -qv \
			'GPL( v2)?$|Dual BSD/GPL$|Dual MPL/GPL$|GPL and additional rights$' && \
			echo "Module $_kmodule has incorrect license." >&2 && exit 1

		# Collect module symbol reference info for later usage
		case "$kmodule" in */drivers/*) nm -upA "$_kmodule" ;;
		esac | sed -n 's,^.*/\([^/]*\.ko\):  *U \(.*\)$,\1 \2,p' >> drivers.undef
	done || exit $?

	# Generate a list of modules for block and networking.
	collect_modules_list() {
		sed -r -n -e "s/^([^ ]+) \\.?($2)\$/\\1/p" drivers.undef |
			LC_ALL=C sort -u > $KernModule/modules.$1
		if [ ! -z "$3" ]; then
			sed -r -e "/^($3)\$/d" -i $KernModule/modules.$1
		fi
	}

	collect_modules_list networking \
		'register_netdev|ieee80211_register_hw|usbnet_probe|phy_driver_register|rt(l_|2x00)(pci|usb)_probe|register_netdevice'
	collect_modules_list block \
		'ata_scsi_ioctl|scsi_add_host|scsi_add_host_with_dma|blk_alloc_queue|blk_init_queue|register_mtd_blktrans|scsi_esp_register|scsi_register_device_handler|blk_queue_physical_block_size' \
		'pktcdvd.ko|dm-mod.ko'
	collect_modules_list drm \
		'drm_open|drm_init'
	collect_modules_list modesetting \
		'drm_crtc_init'
	# Finish preparing the kernel module files

	###### Install kernel core components #############################
	mkdir -p %{buildroot}/boot
	install -m 644 $_KernBuild/.config config
	install -m 644 $_KernBuild/.config %{buildroot}/boot/config-$KernUnameR
	install -m 644 $_KernBuild/System.map System.map
	install -m 644 $_KernBuild/System.map %{buildroot}/boot/System.map-$KernUnameR

	# Install RUE module probe file
	mkdir -p %{buildroot}%{_modulesloaddir}
	install -m 644 %{SOURCE40} %{buildroot}%{_modulesloaddir}/rue.conf

	# NOTE: If we need to sign the vmlinuz, this is the place to do it.
	%ifarch aarch64
	INSTALL_DTB_ARCH_PATH=$_KernBuild/arch/arm64/boot/dts
	install -m 644 $_KernBuild/arch/arm64/boot/Image vmlinuz
	%endif

	%ifarch riscv64
	INSTALL_DTB_ARCH_PATH=$_KernBuild/arch/riscv/boot/dts
	install -m 644 $_KernBuild/arch/riscv/boot/Image vmlinuz
	%endif

	%ifarch x86_64
	INSTALL_DTB_ARCH_PATH=
	install -m 644 $_KernBuild/arch/x86/boot/bzImage vmlinuz
	%endif

	%ifarch loongarch64
	INSTALL_DTB_ARCH_PATH=
	strip -s $_KernBuild/vmlinux -o $_KernBuild/vmlinux.elf
	install -m 644 $_KernBuild/vmlinux.elf vmlinuz
	%endif

	# Install Arch DTB if exists
	if [ -n "$INSTALL_DTB_ARCH_PATH" ]; then
		pushd $INSTALL_DTB_ARCH_PATH || :
		find . -name "*.dtb" | while read -r dtb; do
			mkdir -p %{buildroot}/boot/dtb-$KernUnameR/$(dirname $dtb)
			cp $dtb %{buildroot}/boot/dtb-$KernUnameR/$(dirname $dtb)
		done
		popd
	fi

	# Sign the vmlinuz for supporting secure boot feature only when
	# external efi secure boot signer provided.
	%if 0%{?_sb_signer:1}
	%{_sb_signer vmlinuz vmlinuz.signed}
	mv vmlinuz.signed vmlinuz
	%endif

	# Install Arch vmlinuz
	install -m 644 vmlinuz %{buildroot}/boot/vmlinuz-$KernUnameR

	sha512hmac %{buildroot}/boot/vmlinuz-$KernUnameR | sed -e "s,%{buildroot},," > .vmlinuz.hmac
	cp .vmlinuz.hmac %{buildroot}/boot/.vmlinuz-$KernUnameR.hmac

	###### Doc and certs #############################
	mkdir -p %{buildroot}/%{_datadir}/doc/kernel-keys/$KernUnameR
	if [ -e $_KernBuild/certs/signing_key.x509 ]; then
		install -m 0644 $_KernBuild/certs/signing_key.x509 %{buildroot}/%{_datadir}/doc/kernel-keys/$KernUnameR/kernel-signing-ca.cer
%if %{with_keypkg}
		if [ -e $_KernBuild/certs/signing_key.pem ]; then
			install -m 0644 $_KernBuild/certs/signing_key.pem %{buildroot}/%{_datadir}/doc/kernel-keys/$KernUnameR/kernel-signing-ca.pem
		fi
%else
		echo "# This is a dummy file as private key is not exported." > %{buildroot}/%{_datadir}/doc/kernel-keys/$KernUnameR/kernel-signing-ca.pem
%endif
	fi

	###### kABI checking and packaging #############################
	# Always create the kABI metadata for use in packaging
	echo "**** GENERATING kernel ABI metadata ****"
	gzip -c9 < $_KernBuild/Module.symvers > symvers.gz
	cp symvers.gz %{buildroot}/boot/symvers-$KernUnameR.gz

	###### End of installing kernel modules and core
	popd
}

CheckKernelABI() {
	echo "**** kABI checking is enabled. ****"
	if ! [ -s "$1" ]; then
		echo "**** But cannot find reference Module.kabi file. ****"
	else
		cp $1 %{buildroot}/Module.kabi
		%{SOURCE30} -k %{buildroot}/Module.kabi -s $_KernBuild/Module.symvers || exit 1
		rm %{buildroot}/Module.kabi
	fi
}

InstKernelDevel() {
	###### Install kernel-devel package ###############################
	### TODO: need tidy up
	### Save the headers/makefiles etc for building modules against.
	# This all looks scary, but the end result is supposed to be:
	# * all arch relevant include/ files
	# * all Makefile/Kconfig files
	# * all script/ files

	# `modules_install` will symlink build to $_KernBuild, and source to $_KernSrc, remove the symlinks first
	rm -rf $KernModule/{build,source}
	mkdir -p $KernModule/{extra,updates,weak-updates}

	# Symlink $KernDevel to kernel module build path
	ln -sf /usr/src/kernels/$KernUnameR $KernModule/build
	ln -sf /usr/src/kernels/$KernUnameR $KernModule/source

	# Start installing kernel devel files
	mkdir -p $KernDevel
	pushd $KernDevel

	# First copy everything
	(cd $_KernSrc; cp --parents $(find . -type f -name "Makefile*" -o -name "Kconfig*" -o -name "Kbuild*") $KernDevel/)
	# Copy built config and sym files
	cp $_KernBuild/Module.symvers .
	cp $_KernBuild/System.map .
	cp $_KernBuild/.config .
	if [ -s $_KernBuild/Module.markers ]; then
		cp $_KernBuild/Module.markers .
	fi

	# We may want to keep Documentation, I got complain from users of missing Makefile
	# of Documentation when building custom module with document.
	# rm -rf build/Documentation
	# Script files
	rm -rf scripts
	cp -a $_KernSrc/scripts .
	cp -a $_KernBuild/scripts .

	# Include files
	rm -rf include
	cp -a $_KernSrc/include .
	cp -a $_KernBuild/include/config include/
	cp -a $_KernBuild/include/generated include/

	# SELinux
	mkdir -p security/selinux/
	cp -a $_KernSrc/security/selinux/include security/selinux/

	# Set arch name
	Arch=$(head -4 $_KernBuild/.config | sed -ne "s/.*Linux\/\([^\ ]*\).*/\1/p" | sed -e "s/x86_64/x86/" )

	# Arch include
	mkdir -p arch/$Arch
	cp -a $_KernSrc/arch/$Arch/include arch/$Arch/
	cp -a $_KernBuild/arch/$Arch/include arch/$Arch/

	if [ -d $_KernBuild/arch/$Arch/scripts ]; then
		cp -a $_KernBuild/arch/$Arch/scripts arch/$Arch/ || :
	fi

	# Kernel module build dependency
	if [ -f $_KernBuild/tools/objtool/objtool ]; then
		cp -a $_KernBuild/tools/objtool/objtool tools/objtool/ || :
	fi

	if [ -f $_KernBuild/tools/objtool/fixdep ]; then
		cp -a $_KernBuild/tools/objtool/fixdep tools/objtool/ || :
	fi

	cp -a $_KernSrc/arch/$Arch/*lds arch/$Arch/ &>/dev/null || :
	cp -a $_KernBuild/arch/$Arch/*lds arch/$Arch/ &>/dev/null || :

	mkdir -p arch/$Arch/kernel
	if [ -f $_KernSrc/arch/$Arch/kernel/module.lds ]; then
		cp -a $_KernSrc/arch/$Arch/kernel/module.lds arch/$Arch/kernel/
	fi
	if [ -f $_KernBuild/arch/$Arch/kernel/module.lds ]; then
		cp -a $_KernBuild/arch/$Arch/kernel/module.lds arch/$Arch/kernel/
	fi

	# Symlink include/asm-$Arch for better compatibility with some old system
	ln -sfr arch/$Arch include/asm-$Arch

	# Make sure the Makefile and version.h have a matching timestamp so that
	# external modules can be built
	touch -r Makefile include/generated/uapi/linux/version.h
	touch -r .config include/linux/autoconf.h

	# If we have with_modsign, the key should be installed under _datadir, make a symlink here:
	if [ -e %{buildroot}/%{_datadir}/doc/kernel-keys/$KernUnameR/kernel-signing-ca.cer ]; then
		mkdir -p certs
		ln -sf %{_datadir}/doc/kernel-keys/$KernUnameR/kernel-signing-ca.cer signing_key.x509
		ln -sf %{_datadir}/doc/kernel-keys/$KernUnameR/kernel-signing-ca.cer certs/signing_key.x509
		ln -sf %{_datadir}/doc/kernel-keys/$KernUnameR/kernel-signing-ca.pem signing_key.pem
		ln -sf %{_datadir}/doc/kernel-keys/$KernUnameR/kernel-signing-ca.pem certs/signing_key.pem
	fi


	# Delete obj files
	find . -iname "*.o" -o -iname "*.cmd" -delete

	# Done
	popd
}

InstKernelHeaders () {
	%{kernel_make} headers_install
	find %{buildroot}/usr/include \
		\( -name .install -o -name .check -o \
		-name ..install.cmd -o -name ..check.cmd \) -delete
}

InstPerf () {
	%{perf_make} -C tools/perf install-bin install-python_ext install-man

	# remove the 'trace' symlink.
	rm -f %{buildroot}%{_bindir}/trace

	# Be just like CentOS:
	# remove any tracevent files, eg. its plugins still gets built and installed,
	# even if we build against system's libtracevent during perf build (by setting
	# LIBTRACEEVENT_DYNAMIC=1 above in perf_make macro). Those files should already
	# ship with libtraceevent package.
	rm -rf %{buildroot}%{_libdir}/traceevent
}

InstTools() {
	%{tools_make} -C tools/power/cpupower DESTDIR=%{buildroot} libdir=%{_libdir} mandir=%{_mandir} CPUFREQ_BENCH=false install
	rm -f %{buildroot}%{_libdir}/*.{a,la}
	%find_lang cpupower
	mv cpupower.lang ../

%ifarch x86_64
	pushd tools/power/cpupower/debug/x86_64
	install -m755 centrino-decode %{buildroot}%{_bindir}/centrino-decode
	install -m755 powernow-k8-decode %{buildroot}%{_bindir}/powernow-k8-decode
	popd
%endif

	chmod 0755 %{buildroot}%{_libdir}/libcpupower.so*
	mkdir -p %{buildroot}%{_unitdir} %{buildroot}%{_sysconfdir}/sysconfig
	install -m644 %{SOURCE2000} %{buildroot}%{_unitdir}/cpupower.service
	install -m644 %{SOURCE2001} %{buildroot}%{_sysconfdir}/sysconfig/cpupower

%ifarch x86_64
	mkdir -p %{buildroot}%{_mandir}/man8
	%{tools_make} -C tools/power/x86/x86_energy_perf_policy DESTDIR=%{buildroot} install
	%{tools_make} -C tools/power/x86/turbostat DESTDIR=%{buildroot} install
	%{tools_make} -C tools/power/x86/intel-speed-select DESTDIR=%{buildroot} install
%endif

	%{tools_make} -C tools/thermal/tmon install
	%{tools_make} -C tools/iio install
	%{tools_make} -C tools/gpio install

	pushd tools/mm/
	install -m755 slabinfo %{buildroot}%{_bindir}/slabinfo
	install -m755 page_owner_sort %{buildroot}%{_bindir}/page_owner_sort
	popd
	# with_tools
}

InstBpfTool () {
	%{bpftool_make} -C tools/bpf/bpftool bash_compdir=%{_sysconfdir}/bash_completion.d/ mandir=%{_mandir} install doc-install
}

CollectKernelFile() {
	###### Collect file list #########################################
	pushd %{buildroot}

	# Collect all module files, dtb files, and dirs
	{
		# Install certs in core package if found
		# Echo a dir so it don't fail as a empty list if signing is disabled.
		echo "%%dir %{_datadir}/doc/kernel-keys"
		if [ -e "%{buildroot}/%{_datadir}/doc/kernel-keys/%{kernel_unamer}/kernel-signing-ca.cer" ]; then
			echo %{_datadir}/doc/kernel-keys/%{kernel_unamer}/kernel-signing-ca.cer
		fi

		find lib/modules/$KernUnameR/ boot/dtb-$KernUnameR/ -not -type d -printf '/%%p\n' 2>/dev/null
		find lib/modules/$KernUnameR/ boot/dtb-$KernUnameR/ -type d -printf '%%%%dir /%%p\n' 2>/dev/null
	} | sort -u > core.list

	# Install private key in cert package if found
	# Echo a dir so it don't fail as a empty list if signing is disabled.
	echo "%%dir %{_datadir}/doc/kernel-keys" >> signing-keys.list
	if [ -e "%{buildroot}/%{_datadir}/doc/kernel-keys/%{kernel_unamer}/kernel-signing-ca.pem" ]; then
%if %{with_keypkg}
		echo %{_datadir}/doc/kernel-keys/%{kernel_unamer}/kernel-signing-ca.pem >> signing-keys.list
%else
		# Dummy key goes to kernel-core pkg, kernel-keys dir created above
		echo %{_datadir}/doc/kernel-keys/%{kernel_unamer}/kernel-signing-ca.pem >> core.list
%endif
	fi

	# Do module splitting, filter-modules.sh will generate a list of
	# modules to be split into external module package
	# Rest of the modules stay in core package
	%SOURCE10 "%{buildroot}" "$KernUnameR" "%{_target_cpu}" "$_KernBuild/System.map" non-core-modules >> modules.list || exit $?

	comm -23 core.list modules.list > core.list.tmp
	mv core.list.tmp core.list

	popd

	# Make these file list usable in rpm build dir
	mv %{buildroot}/*.list ../
}

## Build MLNX OFED
BuildInstMLNXOFED() {
	inst_mod() {
		src_mod=$1
		src_mod_name=$(basename "$src_mod")
		dest=""

		# Replace old module
		for mod in $(find $KernModule -name "*$src_mod_name*"); do
			echo "MLNX_OFED: REPLACING: kernel module $mod"
			dest=$(dirname "$mod")
			rm -f "$mod"
		done

		# Install new module
		if [ ! -d "$dest" ]; then
			echo "MLNX_OFED: NEW: kernel module $dest/$mod"
			dest="$KernModule/kernel/drivers/ofed_addon"
			mkdir -p $dest
		fi

		cp -f "$src_mod" "$dest/"
	}

	handle_rpm() {
		rm -rf extracted
		mkdir -p extracted && pushd extracted

		rpm2cpio $1 | cpio -id
		find . -name "*.ko" -or -name "*.ko.xz" | while read -r mod; do
			inst_mod "$mod"
		done
		# find . -name "*.debug" | while read -r mod; do
		#       inst_debuginfo "$mod"
		# done

		popd
	}

	pushd drivers/thirdparty/release-drivers/mlnx
	MLNX_OFED_VERSION=$(./get_mlnx_info.sh mlnx_version) ; 	MLNX_OFED_TGZ_NAME=$(./get_mlnx_info.sh mlnx_tgz_name)
	tar -xzvf $MLNX_OFED_TGZ_NAME
	pushd MLNX_OFED_LINUX-${MLNX_OFED_VERSION}-rhel9.4-x86_64
	pushd src
	echo "tar -xzvf MLNX_OFED_SRC-${MLNX_OFED_VERSION}.tgz"
	tar -xzvf MLNX_OFED_SRC-${MLNX_OFED_VERSION}.tgz
	pushd MLNX_OFED_SRC-${MLNX_OFED_VERSION}

	# Fix TS4 compile errors by enabling LTO. So, disable LTO,  and enabling -fPIE.
	DISTRO=$(echo "%{?dist}" | sed "s/\.//g")
	if [[ "${DISTRO}" != "tl3" ]]; then
		## "${DISTRO}" == "tl4" or "${DISTRO}" == "oc9"
		sed -i "s/rpmbuild --rebuild/rpmbuild --define 'rhel 9' --define '_lto_cflags -fno-lto' --define '_hardened_cflags -fPIE' --rebuild/g" ./install.pl
	fi
	# Unset $HOME, when doing koji build, koji insert special macros into ~/.rpmmacros that will break MLNX installer:
	# Koji sets _rpmfilename  %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm,
	# But the installer assumes "_rpmfilename %{_build_name_fmt}" so it will fail to find the built rpm.
	HOME= ./install.pl --build-only --kernel-only --without-depcheck --distro $DISTRO \
	--kernel $KernUnameR --kernel-sources $KernDevel \
	--without-mlx5_fpga_tools --without-mlnx-rdma-rxe --without-mlnx-nfsrdma \
	--without-mlnx-nvme --without-isert --without-iser --without-srp --without-rshim --without-mdev \
	--disable-kmp

	# get all kernel module rpms that were built against target kernel
	find RPMS -name "*.rpm" -type f | while read -r pkg; do
		if rpm -qlp $pkg | grep "\.ko"; then
			handle_rpm "$(realpath $pkg)"
		fi
	done

	popd ## MLNX_OFED_SRC*
	rm -rf MLNX_OFED_SRC-${MLNX_OFED_VERSION}
	popd ## src

	echo "Begin to build $MLNX_OFED_TGZ_NAME"
	## Now, we in MLNX_OFED_LINUX-* dir!
	%if %{with_modsign}
	%ifarch x86_64
	# The purpose is to reorgnise the mlnx tgz files for our TencentOS
	# Build the full packages of mlnx ofed.
	# change to build/
	tmp=%{buildroot}/tmp
	mkdir $tmp
	tmppath=$(realpath $tmp)

	# We need to jump the root privilege because we'll assign a normal tmpdir
	sed -i 's/$UID -ne 0/! -z $JUMP_ROOT/g' mlnx_add_kernel_support.sh
	if [ "${DISTRO}" != "tl3" ]; then
		sed -i '/# Check for needed packages by install.pl/a sed -i "s/rpmbuild --rebuild/rpmbuild --define '\''rhel 9'\'' --define '\''_lto_cflags -fno-lto'\'' --define '\''_hardened_cflags -fPIE'\'' --rebuild/g" ${ofed}/install.pl' mlnx_add_kernel_support.sh
	fi
	sed -i 's/\(ex ${ofed}\/install\.pl\)/\1 --without-mlnx-nvme/g' mlnx_add_kernel_support.sh

	# unset home
	if [[ "${DISTRO}" != "tl3" ]]; then
		## "${DISTRO}" == "tl4" or "${DISTRO}" == "oc9"
		HOME= ./mlnx_add_kernel_support.sh -m ./ --distro rhel9.4 --make-tgz -y \
			--kernel $KernUnameR --kernel-sources $KernDevel --skip-repo --tmpdir $tmppath
	else
		## "${DISTRO}" == "tl3"
		HOME= ./mlnx_add_kernel_support.sh -m ./ --make-tgz -y \
			--kernel $KernUnameR --kernel-sources $KernDevel --skip-repo --tmpdir $tmppath
	fi

	# Prepare first
	pushd $tmppath
	tar -xzvf MLNX_OFED_LINUX-*
	touch ko.location
	# compatible with module signer script
	signed=ko_files/lib/modules/$KernUnameR
	mkdir -p workdir $signed

	# Extract all the rpms containing ko files to workdir
	rpm_rp=$(realpath MLNX_OFED_LINUX-*/RPMS)
	pushd workdir
	find $rpm_rp -name "*.rpm" -type f | while read -r pkg; do
		if rpm -qlp $pkg | grep "\.ko$" | grep "6.6" >> ../ko.location; then
			rpm_bn=$(basename $pkg)
			mkdir $rpm_bn && pushd $rpm_bn
			rpm2cpio $rpm_rp/$rpm_bn | cpio -id
			popd ## $rpm_bn
		fi
	done
	popd ## workdir

	# Start collecting all the ko files
	find workdir/ -name "*.ko" | while read -r mod; do
		mv $mod $signed/
	done

	# Now we're about to sign them.
	%{_module_signer} "$KernUnameR" "$_KernBuild" "ko_files" x509 || exit $?

	# Compress it into a new tgz file.
	if [[ "${DISTRO}" != "tl3" ]]; then
		## "${DISTRO}" == "tl4" or "${DISTRO}" == "oc9"
		mlnxfulname=$(basename %{SOURCE3001})
		mlnxrelease=${mlnxfulname%.*}
	else
		## "${DISTRO}" == "tl3"
		mlnxrelease=MLNX_OFED_LINUX-${MLNX_OFED_VERSION}-tencent-x86_64
	fi
	mv $mlnxrelease-ext  $mlnxrelease-ext.$KernUnameR/
	# Turn it back to the original file
	sed -i 's/! -z $JUMP_ROOT/$UID -ne 0/g' $mlnxrelease-ext.$KernUnameR/mlnx_add_kernel_support.sh
	cp -r $signed $mlnxrelease-ext.$KernUnameR/ko_files.signed
	sed -i "s/KERNELMODULE_REPLACE/$KernUnameR/g" %{SOURCE3002}
	cp -r ko.location %{SOURCE3002} $mlnxrelease-ext.$KernUnameR/
	tar -zcvf $mlnxrelease-ext.$KernUnameR.tgz $mlnxrelease-ext.$KernUnameR
	mkdir %{buildroot}/mlnx/
	install -m 755 $mlnxrelease-ext.$KernUnameR.tgz %{buildroot}/mlnx/

	popd ## $tmppath
	rm -rf $tmppath
	%endif
	%endif

	popd ## MLNX_OFED_LINUX-${MLNX_OFED_VERSION}-rhel9.4-x86_64
	rm -rf MLNX_OFED_LINUX-*
	popd ## drivers/thirdparty/release-drivers/mlnx
}

###### Start Kernel Install

%if %{with_core}
InstKernelBasic

%if %{with_kabichk}
{{KABICHECKSPEC}} # `CheckKernelABI <Module.kabi from KABISOURCESPEC>`
%endif

InstKernelDevel
%endif

%if %{with_headers}
InstKernelHeaders
%endif

%if %{with_ofed}
# MLNXOFED driver's Makefile doesn't support cross build.
%if !%{with_crossbuild}
BuildInstMLNXOFED
%endif
%endif

%if %{with_perf}
InstPerf
%endif

%if %{with_tools}
InstTools
%endif

%if %{with_bpftool}
InstBpfTool
%endif

%if %{with_core}
CollectKernelFile
%endif

###### Debuginfo ###############################################################
%if %{with_debuginfo}

###### Kernel core debuginfo #######
%if %{with_core}
mkdir -p %{buildroot}%{debuginfo_dir}/lib/modules/$KernUnameR
cp -rpf $_KernBuild/vmlinux %{buildroot}%{debuginfo_dir}/lib/modules/$KernUnameR/vmlinux
ln -sf %{debuginfo_dir}/lib/modules/$KernUnameR/vmlinux %{buildroot}/boot/vmlinux-$KernUnameR
%endif
#with_core

# All binary installation are done here, so run __debug_install_post, then undefine it.
# This triggers find-debuginfo.sh, undefine prevents it from being triggered again
# in post %%install. we do this here because we need to compress and sign modules
# after the debuginfo extraction.
%__debug_install_post

# Delete the debuginfo for kernel-devel files
rm -rf %{buildroot}%{debuginfo_dir}/usr/src

%undefine __debug_install_post
%global __debug_install_post %{nil}

###### Finally, module sign and compress ######
%if %{with_modsign} && %{with_core}
### Sign after debuginfo extration, extraction breaks signature
%{_module_signer} "$KernUnameR" "$_KernBuild" "%{buildroot}" || exit $?
%endif

### Compression after signing, compressed module can't be signed
# Spawn at most 16 workers, at least 2 workers, each worker compress 4 files
NPROC=$(nproc --all)
[ "$NPROC" ] || NPROC=2
[ "$NPROC" -gt 16 ] && NPROC=16
find "$KernModule" -type f -name '*.ko' -print0 | xargs -0r -P${NPROC} -n4 xz -T1;

### Change module path in file lists
for list in ../*.list; do
	sed -i -e 's/\.ko$/\.ko.xz/' $list
done

%endif
#with_debuginfo

###### RPM scriptslets #########################################################
### Core package
# Pre
%if %{with_core}
%pre core
# Best effort try to avoid installing with wrong arch
if command -v uname > /dev/null; then
	system_arch=$(uname -m)
	if [ %{_target_cpu} != $system_arch ]; then
		echo "WARN: This kernel is built for %{_target_cpu}. but your system is $system_arch." > /dev/stderr
	fi
fi

%post core
touch %{_localstatedir}/lib/rpm-state/%{name}-%{version}-%{version}%{?dist}.installing_core

%posttrans core
# Weak modules
if command -v weak-modules > /dev/null; then
	weak-modules --add-kernel %{kernel_unamer} || exit $?
fi
# Boot entry and depmod files
if command -v kernel-install > /dev/null; then
	kernel-install add %{kernel_unamer} /lib/modules/%{kernel_unamer}/vmlinuz
elif command -v new-kernel-pkg > /dev/null; then
	new-kernel-pkg --package kernel --install %{kernel_unamer} --kernel-args="crashkernel=512M-12G:128M,12G-64G:256M,64G-128G:512M,128G-:768M" --make-default || exit $?
	new-kernel-pkg --package kernel --mkinitrd --dracut --depmod --update %{kernel_unamer} || exit $?
else
	echo "NOTICE: No available kernel install handler found. Please make sure boot loader and initramfs are properly configured after the installation." > /dev/stderr
fi
# Just in case kernel-install didn't depmod
depmod -A %{kernel_unamer}
# Core install done
rm -f %{_localstatedir}/lib/rpm-state/%{name}-%{version}-%{version}%{?dist}.installing_core

# XXX: Workaround for TLinux 2.x, TLinux 2.x has broken SELinux rule, enabling SELinux will cause boot failure.
%if "%{?dist}" == ".tl2"
if command -v grubby > /dev/null; then
	grubby --update-kernel /boot/vmlinuz-%{kernel_unamer} --args selinux=0
else
	echo "NOTICE: TL2 detected, but grubby is missing, please set selinux=0 for new installed kernel manually, or it may fail to boot due to broken SELinux rule." > /dev/stderr
fi
%endif

# Some system still expect us to setup vmlinuz manually, vmlinuz is listed
# as ghost file to detect such systems
if [ ! -e /boot/vmlinuz-%{kernel_unamer} ]; then
	cp /lib/modules/%{kernel_unamer}/vmlinuz /boot/vmlinuz-%{kernel_unamer}
	cp /lib/modules/%{kernel_unamer}/config /boot/config-%{kernel_unamer}
	cp /lib/modules/%{kernel_unamer}/System.map /boot/System.map-%{kernel_unamer}
	ln -srf /boot/vmlinuz-%{kernel_unamer} /boot/vmlinuz
	ln -srf /boot/config-%{kernel_unamer} /boot/config
	ln -srf /boot/System.map-%{kernel_unamer} /boot/System.map
fi

%preun core
# Boot entry and depmod files
if command -v kernel-install > /dev/null; then
	kernel-install remove %{kernel_unamer} /lib/modules/%{kernel_unamer}/vmlinuz || exit $?
elif command -v new-kernel-pkg > /dev/null; then
	/sbin/new-kernel-pkg --rminitrd --dracut --remove %{kernel_unamer}
else
	echo "NOTICE: No available kernel uninstall handler found. Please make sure boot loader and initramfs are properly cleared after the uninstallation." > /dev/stderr
fi

# Weak modules
if command -v weak-modules > /dev/null; then
	weak-modules --remove-kernel %{kernel_unamer} || exit $?
fi

### Module package
%pre modules
# In TS private release, kernel command line in /etc/default/grub will add "tk_private=1".
# When install TS private release, do not need install "usb-storage nouveau cfg80211" into initramfs.
tk_private_val=1
grep -q "tk_private=1" /etc/default/grub 2>/dev/null || tk_private_val=0
if (( $tk_private_val == 1 )); then echo "omit_dracutmodules+=\" usb-storage nouveau cfg80211 \"" >> /etc/dracut.conf ; fi

%post modules
depmod -a %{kernel_unamer}
if [ ! -f %{_localstatedir}/lib/rpm-state/%{name}-%{version}-%{version}%{?dist}.installing_core ]; then
	touch %{_localstatedir}/lib/rpm-state/%{name}-%{version}-%{version}%{?dist}.need_to_run_dracut
fi
# Because /lib link to /usr/lib, /lib/modules is the same to /usr/lib/modules.
# So, in TS private release, we only delete usb-storage and nouveau module in /usr/lib/modules dir.
rm_public_ko=1
grep -q "omit_dracutmodules+=\" usb-storage nouveau cfg80211 \"" /etc/dracut.conf 2>/dev/null || rm_public_ko=0
if (( $rm_public_ko == 1 )); then
	sed -i '/omit_dracutmodules+=\" usb-storage nouveau cfg80211 \"/d' /etc/dracut.conf
	rm -f /usr/lib/modules/%{kernel_unamer}/kernel/drivers/usb/storage/*
	rm -f /usr/lib/modules/%{kernel_unamer}/kernel/drivers/gpu/drm/nouveau/*
	rm -f /usr/lib/modules/%{kernel_unamer}/kernel/net/wireless/*
fi

%posttrans modules
if [ -f %{_localstatedir}/lib/rpm-state/%{name}-%{version}-%{version}%{?dist}.need_to_run_dracut ]; then\
	dracut -f --kver "%{kernel_unamer}"
	rm -f %{_localstatedir}/lib/rpm-state/%{name}-%{version}-%{version}%{?dist}.need_to_run_dracut
fi

%postun modules
depmod -a %{kernel_unamer}

### Devel package
%post devel
if [ -f /etc/sysconfig/kernel ]; then
	. /etc/sysconfig/kernel || exit $?
fi
# This hardlink merges same devel files across different kernel packages
if [ "$HARDLINK" != "no" -a -x /usr/bin/hardlink -a ! -e /run/ostree-booted ]; then
	(cd /usr/src/kernels/%{kernel_unamer} && /usr/bin/find . -type f | while read -r f; do
		hardlink /usr/src/kernels/*/$f $f > /dev/null
	done)
fi
%endif

### kernel-tools package
%if %{with_tools}
%post -n kernel-tools-libs
/sbin/ldconfig

%postun -n kernel-tools-libs
/sbin/ldconfig
%endif

###### Rpmbuild packaging file list ############################################
### empty meta-package
%if %{with_core}
%files
%{nil}

%files core -f core.list
%defattr(-,root,root)
# Mark files as ghost in case rewritten after install (eg. by kernel-install script)
%ghost /boot/vmlinuz-%{kernel_unamer}
%ghost /boot/.vmlinuz-%{kernel_unamer}.hmac
/boot/System.map-%{kernel_unamer}
/boot/config-%{kernel_unamer}
/boot/symvers-%{kernel_unamer}.gz
# RUE module probe file
%config(noreplace) %{_modulesloaddir}/rue.conf
# Initramfs will be generated after install
%ghost /boot/initramfs-%{kernel_unamer}.img
%ghost /boot/initramfs-%{kernel_unamer}kdump.img
# Make depmod files ghost files of the core package
%dir /lib/modules/%{kernel_unamer}
%ghost /lib/modules/%{kernel_unamer}/modules.alias
%ghost /lib/modules/%{kernel_unamer}/modules.alias.bin
%ghost /lib/modules/%{kernel_unamer}/modules.builtin.bin
%ghost /lib/modules/%{kernel_unamer}/modules.builtin.alias.bin
%ghost /lib/modules/%{kernel_unamer}/modules.dep
%ghost /lib/modules/%{kernel_unamer}/modules.dep.bin
%ghost /lib/modules/%{kernel_unamer}/modules.devname
%ghost /lib/modules/%{kernel_unamer}/modules.softdep
%ghost /lib/modules/%{kernel_unamer}/modules.symbols
%ghost /lib/modules/%{kernel_unamer}/modules.symbols.bin
%{!?_licensedir:%global license %%doc}
%license %{kernel_tarname}/COPYING.%{kernel_unamer}

%files modules -f modules.list
%defattr(-,root,root)

%if %{with_keypkg}
%files signing-keys -f signing-keys.list
%defattr(-,root,root)
%endif

%files devel
%defattr(-,root,root)
/usr/src/kernels/%{kernel_unamer}

%if %{with_debuginfo}
%files debuginfo -f debuginfo.list
%defattr(-,root,root)
/boot/vmlinux-%{kernel_unamer}
%endif
# with_core
%endif

%if %{with_debuginfo}
%files debuginfo-common -f debugfiles.list
%defattr(-,root,root)
%endif

%if %{with_headers}
%files headers
%defattr(-,root,root)
/usr/include/*
%endif

%if %{with_perf}
%files -n perf
%defattr(-,root,root)
%{_bindir}/perf*
%{_libdir}/libperf-jvmti.so
%dir %{_libexecdir}/perf-core
%{_libexecdir}/perf-core/*
%{_datadir}/perf-core/*
%{_mandir}/man[1-8]/perf*
%{_sysconfdir}/bash_completion.d/perf
%{_docdir}/perf-tip/tips.txt
# TODO: Missing doc?
# %%doc linux-%%{kernel_unamer}/tools/perf/Documentation/examples.txt

%files -n python3-perf
%defattr(-,root,root)
%{python3_sitearch}/*

%if %{with_debuginfo}
%files -f perf-debuginfo.list -n perf-debuginfo
%defattr(-,root,root)

%files -f python3-perf-debuginfo.list -n python3-perf-debuginfo
%defattr(-,root,root)
%endif
# with_perf
%endif

%if %{with_tools}
%files -n kernel-tools -f cpupower.lang
%defattr(-,root,root)
%{_bindir}/cpupower
%{_datadir}/bash-completion/completions/cpupower
%ifarch x86_64
%{_bindir}/centrino-decode
%{_bindir}/powernow-k8-decode
%endif
%{_unitdir}/cpupower.service
%{_mandir}/man[1-8]/cpupower*
%config(noreplace) %{_sysconfdir}/sysconfig/cpupower
%ifarch x86_64
%{_bindir}/x86_energy_perf_policy
%{_mandir}/man8/x86_energy_perf_policy*
%{_bindir}/turbostat
%{_mandir}/man8/turbostat*
%{_bindir}/intel-speed-select
%endif
%{_bindir}/tmon
%{_bindir}/iio_event_monitor
%{_bindir}/iio_generic_buffer
%{_bindir}/lsiio
%{_bindir}/lsgpio
%{_bindir}/gpio-*
%{_bindir}/page_owner_sort
%{_bindir}/slabinfo

%files -n kernel-tools-libs
%defattr(-,root,root)
%{_libdir}/libcpupower.so
%{_libdir}/libcpupower.so.*

%files -n kernel-tools-libs-devel
%defattr(-,root,root)
%{_includedir}/cpufreq.h

%if %{with_debuginfo}
%files -f kernel-tools-debuginfo.list -n kernel-tools-debuginfo
%defattr(-,root,root)
%endif
# with_tools
%endif

%if %{with_bpftool}
%files -n bpftool
%defattr(-,root,root)
%{_sbindir}/bpftool
%{_sysconfdir}/bash_completion.d/bpftool
%{_mandir}/man8/bpftool.8.*
%{_mandir}/man8/bpftool-*.8.*

%if %{with_debuginfo}
%files -f bpftool-debuginfo.list -n bpftool-debuginfo
%defattr(-,root,root)
%endif
# with_bpftool
%endif

%if %{with_ofed}
%ifarch x86_64
%files -n mlnx-ofed-dist
%if "%{?dist}" != ".tl3"
/mlnx/MLNX_OFED_LINUX-23.10-3.2.2.0-rhel9.4-x86_64-ext.%{kernel_unamer}.tgz
%else
/mlnx/MLNX_OFED_LINUX-23.10-3.2.2.0-tencent-x86_64-ext.%{kernel_unamer}.tgz
%endif
%endif
%endif

###### Changelog ###############################################################
%changelog
{{CHANGELOGSPEC}}
