#!/bin/bash

mlnx_version="23.10-3.2.2.0"

mlnx_tgz_name="MLNX_OFED_LINUX-$mlnx_version-rhel9.4-x86_64.tgz"

if [[ $1 == mlnx_url ]]; then
	mlnx_url="https://content.mellanox.com/ofed/MLNX_OFED-$mlnx_version/$mlnx_tgz_name"
elif [[ $1 == mlnx_version ]]; then
	echo $mlnx_version
	exit 0
elif [[ $1 == mlnx_tgz_name ]]; then
	echo $mlnx_tgz_name
	exit 0
else
	echo "Error: wrong parameter for release-drivers/mlnx/get_mlnx_tgz_url.sh!"
	exit 1
fi

echo "$mlnx_url"
