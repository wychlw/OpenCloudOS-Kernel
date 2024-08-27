#!/bin/bash

check_url_reachable()
{
	curl -I https://gitee.com 1>/dev/null 2>&1 || exit 0
}

thirdparty_mlnx(){
	mlnx_tgz_url=$(../../drivers/thirdparty/release-drivers/mlnx/get_mlnx_info.sh mlnx_url)
	mlnx_tgz_name=$(../../drivers/thirdparty/release-drivers/mlnx/get_mlnx_info.sh mlnx_tgz_name)
	get_mlnx_tgz_ok=1

	if [ $(stat -c%s ${mlnx_tgz_name}) -gt 1024 ]; then return 0; fi
	mv ${mlnx_tgz_name} ${mlnx_tgz_name}_ori
	timeout 600 wget -q $mlnx_tgz_url || get_mlnx_tgz_ok=0

	if (( $get_mlnx_tgz_ok == 0 )); then
		mv -f ${mlnx_tgz_name}_ori ${mlnx_tgz_name} ; exit 0
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
