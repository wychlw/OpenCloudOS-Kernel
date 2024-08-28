#!/bin/bash

check_url_reachable()
{
	curl -I https://content.mellanox.com 1>/dev/null 2>&1
	if (( $? != 0 )); then
		echo "Could not reache https://content.mellanox.com"
		exit 1
	fi
}

thirdparty_mlnx(){
	mlnx_tgz_url=$(../../drivers/thirdparty/release-drivers/mlnx/get_mlnx_info.sh mlnx_url)
	mlnx_tgz_name=$(../../drivers/thirdparty/release-drivers/mlnx/get_mlnx_info.sh mlnx_tgz_name)
	mlnx_tgz_sha256=$(../../drivers/thirdparty/release-drivers/mlnx/get_mlnx_info.sh mlnx_tgz_sha256)
	get_mlnx_tgz_ok=1

	if [ $(stat -c%s ${mlnx_tgz_name}) -gt 1024 ]; then return 0; fi
	mv ${mlnx_tgz_name} ${mlnx_tgz_name}_ori
	timeout 900 wget -q $mlnx_tgz_url || get_mlnx_tgz_ok=0

	sha256_tmp=$(sha256sum ${mlnx_tgz_name} | awk '{printf $1}')
	if [[ $sha256_tmp != $mlnx_tgz_sha256 ]]; then get_mlnx_tgz_ok=0; fi

	if (( $get_mlnx_tgz_ok == 0 )); then
		mv -f ${mlnx_tgz_name}_ori ${mlnx_tgz_name}
		echo "Download MLNX_OFED_LINUX-*.tgz fail!"
		exit 1
	else
		rm -f ${mlnx_tgz_name}_ori
	fi
}

##
## main , script start run at here.
##
check_url_reachable

thirdparty_mlnx

echo "Having downloaded thirdparty drivers."
