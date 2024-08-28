#!/bin/bash

thirdparty_mlnx(){
	mlnx_tgz_name=$(release-drivers/mlnx/get_mlnx_info.sh mlnx_tgz_name)

	if [ ! -e release-drivers/mlnx/${mlnx_tgz_name} ] ; then
		./download-and-copy-drivers.sh
		mv ${mlnx_tgz_name} release-drivers/mlnx/
	fi
}

thirdparty_bnxt(){
	if [ -e release-drivers/bnxt ]; then
		rm -rf ../../drivers/net/ethernet/broadcom/bnxt
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
if [[ $1 != without_mlnx ]]; then
	thirdparty_mlnx
fi

thirdparty_bnxt
