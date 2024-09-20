#!/bin/bash

# This script may run at dist/sources/ directory or drivers/thirdparty/ directory.
# "make dist-srpm" will run dist-drivers in dist/Makefile, which will cd to dist/sources/ dir
# to run download-and-copy-drivers.sh.
# "make dist-rpm" will run BuildConfig in dist/templates/kernel.template.spec, which will cd
# to drivers/thirdparty/ dir to run download-and-copy-drivers.sh.
mlnx_tgz_url=$(../../drivers/thirdparty/release-drivers/mlnx/get_mlnx_info.sh mlnx_url)
mlnx_tgz_name=$(../../drivers/thirdparty/release-drivers/mlnx/get_mlnx_info.sh mlnx_tgz_name)
mlnx_tgz_sha256=$(../../drivers/thirdparty/release-drivers/mlnx/get_mlnx_info.sh mlnx_tgz_sha256)

check_url_reachable()
{
	curl -I $mlnx_tgz_url 1>/dev/null 2>&1 && return 0

	echo "Try to download ${mlnx_tgz_name} from backup_url."
	mlnx_tgz_url=$(../../drivers/thirdparty/release-drivers/mlnx/get_mlnx_info.sh backup_url)
	curl -I $mlnx_tgz_url 1>/dev/null 2>&1
	if (( $? != 0 )); then
		echo "Could not download ${mlnx_tgz_name} !"
		exit 1
	fi
}

thirdparty_mlnx(){
	get_mlnx_tgz_ok=1

	# Real MLNX_OFED_LINUX-*.tgz will more than 1024 bytes.
	# Dummy MLNX_OFED_LINUX-*.tgz will less than 1024 bytes.
	if [ $(stat -c%s ${mlnx_tgz_name}) -lt 1024 ]; then
		rm -f ${mlnx_tgz_name}
		timeout 900 wget -q $mlnx_tgz_url || get_mlnx_tgz_ok=0
	fi

	sha256_tmp=$(sha256sum ${mlnx_tgz_name} | awk '{printf $1}')
	if [[ $sha256_tmp != $mlnx_tgz_sha256 ]]; then get_mlnx_tgz_ok=0; fi

	if (( $get_mlnx_tgz_ok == 0 )); then
		echo "Download ${mlnx_tgz_name} fail!"
		exit 1
	fi
}

##
## main , script start run at here.
##
check_url_reachable

thirdparty_mlnx

echo "Having downloaded thirdparty drivers."
