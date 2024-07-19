#!/bin/bash

if [ ! -e release-drivers/.git ] ; then
	## If clone git fail, using the kernel native drivers to compile.
	timeout 300 git clone https://gitee.com/OpenCloudOS/release-drivers.git release-drivers/ || exit 0
fi

echo "Having release-drivers git repo, coping the thirdparty driver code to kernel native dir."

if [ -e release-drivers/bnxt ]; then
	rm -rf ../../drivers/net/ethernet/broadcom/bnxt
	cp -a release-drivers/bnxt ../../drivers/net/ethernet/broadcom/

	## Use sed to replace "&& BNXT" with "&& BNXT && !THIRDPARTY_BNXT" in
	## drivers/infiniband/hw/bnxt_re/Kconfig
	## Because compile kernel native bnxt_re will fail when using thirdparty bnxt.
	sed -i 's/\(&& BNXT\)$/\1 \&\& !THIRDPARTY_BNXT/g' ../../drivers/infiniband/hw/bnxt_re/Kconfig
fi
