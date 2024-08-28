#!/bin/bash

mlnx_version="23.10-3.2.2.0"

mlnx_tgz_name="MLNX_OFED_LINUX-$mlnx_version-rhel9.4-x86_64.tgz"
mlnx_tgz_sha256="800b8d0f063558bf943d5b3fabf02cbbfa84a57b2690c2128a10fdaf7636d2dc"

if [[ $1 == mlnx_url ]]; then
	mlnx_url="https://content.mellanox.com/ofed/MLNX_OFED-$mlnx_version/$mlnx_tgz_name"
	echo "$mlnx_url"
	exit 0
elif [[ $1 == mlnx_version ]]; then
	echo $mlnx_version
	exit 0
elif [[ $1 == mlnx_tgz_name ]]; then
	echo $mlnx_tgz_name
	exit 0
elif [[ $1 == mlnx_tgz_sha256 ]]; then
	echo $mlnx_tgz_sha256
	exit 0
else
	echo "Error: wrong parameter for release-drivers/mlnx/get_mlnx_tgz_url.sh!"
	exit 1
fi
