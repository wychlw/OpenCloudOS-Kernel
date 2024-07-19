#!/bin/bash

if [ ! -e release-drivers/.git ] ; then
	timeout 300 git clone https://gitee.com/OpenCloudOS/release-drivers.git release-drivers/
fi

if [ -e release-drivers/bnxt ]; then
	rm -rf ../../drivers/net/ethernet/broadcom/bnxt
	cp -a release-drivers/bnxt ../../drivers/net/ethernet/broadcom/
fi
