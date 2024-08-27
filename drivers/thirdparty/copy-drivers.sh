#!/bin/bash

thirdparty_prepare_source_code(){
	mlnx_tgz_name=$(release-drivers/mlnx/get_mlnx_info.sh mlnx_tgz_name)

	if [ ! -e release-drivers/mlnx/${mlnx_tgz_name} ] ; then
		## This script will only be called when existing ../../dist/sources dir
		if [ $(stat -c%s ../../dist/sources/${mlnx_tgz_name}) -lt 1024 ]; then
			## Real MLNX_OFED_LINUX-*.tgz will more than 1024 bytes.
			## Real MLNX_OFED_LINUX-*.tgz will more than 1024 bytes.
			pushd ../../dist/sources
			./download-and-copy-drivers.sh
			popd
		fi
		cp -a ../../dist/sources/${mlnx_tgz_name} release-drivers/mlnx/
	fi
}

thirdparty_bnxt(){
	if [ -e release-drivers/bnxt ]; then
		rm -rf ../../drivers/net/thirdparty_bnxtethernet/broadcom/bnxt
		cp -a release-drivers/bnxt ../../drivers/net/ethernet/broadcom/

		## Use sed to replace "&& BNXT" with "&& BNXT && !THIRDPARTY_BNXT" in
		## drivers/infiniband/hw/bnxt_re/Kconfig
		## Because compile kernel native bnxt_re will fail when using thirdparty bnxt.
		sed -i 's/\(&& BNXT\)$/\1 \&\& !THIRDPARTY_BNXT/g' ../../drivers/infiniband/hw/bnxt_re/Kconfig
		echo "thirdparty_bnxt: has overriden thirdparty bnxt driver code to kernel native dir."
	fi
}

##
## main , script start run at here.
##
thirdparty_prepare_source_code

thirdparty_bnxt
