#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# 1. Check whether TencentOS Kennel KABI is compatible
# 2. Update TencentOS Kennel KABI file
# 3. Create TencentOS Kennel KABI file
#
RED='\E[1;31m'
GREEN='\E[1;32m'
YELLOW='\E[1;33m'
END='\E[0m'

srctree=$(dirname "$0")/../

function usage_info()
{
	echo "Usage: $0 <type> <arch>"
	echo "  type: check update create"
	echo "  arch: x86 x86_64 arm64"
}

function compile_kernel()
{
	local machine=$1
	local arch=$2
	local thread_num=$(nproc)
	thread_num=$((thread_num * 2))

	if [ "${machine}" == "x86_64" ] && [ "${arch}" == "arm64" ] && [ "X$CROSS_COMPILE" == "X" ]; then
		local CROSS_COMPILE="aarch64-linux-gnu-"
	fi

	make ARCH=${arch} CROSS_COMPILE=${CROSS_COMPILE} tencentconfig tkci.config -sk 1> /dev/null
	if [ $? -ne 0 ]; then
		printf "${RED}make tencentconfig tkci.config failed${END}\n"
		return 1
	fi

	echo "start to compile kernel, may take a long time..."
	make ARCH=${arch} CROSS_COMPILE=${CROSS_COMPILE} -j ${thread_num} -sk 1> /dev/null
	if [ $? -ne 0 ]; then
		printf "${RED}compile kernel failed${END}\n"
		return 1
	fi

	return 0
}

function create_kabi()
{
	local kabi_file=$1
	local core_kabi_list="dist/kabi/core-kabi-list"

	if [ ! -s ${core_kabi_list} ]; then
		printf "${RED}get ${core_kabi_list} failed${END}\n"
		return 1
	fi

	while read kabi
	do
		grep -w ${kabi} Module.symvers 1>> ${kabi_file}
		if [ $? -ne 0 ]; then
			printf "${YELLOW}function ${kabi} miss\n"
		fi
	done < ${core_kabi_list}

	sed -i 's/[[:space:]]*$//' ${kabi_file}
	printf "${GREEN}create KABI file ${kabi_file} success${END}\n"

	return 0
}

function update_kabi()
{
	local kabi_file=$1
	local new_kabi_file=${kabi_file}_new
	local core_kabi_list="dist/kabi/core-kabi-list"

	if [ ! -s ${core_kabi_list} ]; then
		printf "${RED}get ${core_kabi_list} failed${END}\n"
		return 1
	fi

	rm -rf ${new_kabi_file}
	while read kabi
	do
		grep -w ${kabi} Module.symvers 1>> ${new_kabi_file}
		if [ $? -ne 0 ]; then
			printf "${YELLOW}function ${kabi} miss\n"
		fi
	done < ${core_kabi_list}
	sed -i 's/[[:space:]]*$//' ${new_kabi_file}

	diff ${kabi_file} ${new_kabi_file} > /dev/null
	if [ $? -eq 0 ]; then
		rm -rf ${new_kabi_file}
		printf "${YELLOW}KABI file no change, not need update${END}\n"
		return 0
	fi

	mv ${new_kabi_file} ${kabi_file}
	printf "${GREEN}update KABI file ${kabi_file} success${END}\n"

	return 0
}

function check_kabi()
{
	local kabi_file=$1

	./scripts/check-kabi -k ${kabi_file} -s Module.symvers
	if [ $? -ne 0 ]; then
		printf "${RED}check KABI failed${END}\n"
		return 1
	fi
	printf "${GREEN}check KABI success${END}\n"

	return 0
}

function check_param()
{
	local type=$1
	local arch=$2
	local machine=`uname -m`

	if [ "$#" -ne 2 ]; then
		usage_info
		return 1
	fi

	if [ "${type}" != "check" ] && [ "${type}" != "update" ] && [ "${type}" != "create" ]; then
		printf "${RED}not support type:${type}${END}\n"
		usage_info
		return 1
	fi

	if [ "${machine}" != "x86_64" ] && [ "${machine}" != "aarch64" ]; then
		printf "${RED}not support machine:${machine}${END}\n"
		usage_info
		return 1
	fi

	if [ "${arch}" != "x86" ] && [ "${arch}" != "x86_64" ] && [ "${arch}" != "arm64" ]; then
		printf "${RED}not support arch:${arch}${END}\n"
		usage_info
		return 1
	fi

	if [ "${machine}" == "aarch64" ] && [ "${arch}" == "x86" -o "${arch}" == "x86_64" ]; then
		printf "${RED}machine aarch64 not support cross compile${END}\n"
		usage_info
		return 1
	fi

	return 0
}

function main()
{
	local type=$1
	local arch=$2
	local machine=`uname -m`
	local kabi_file=""

	check_param $@
	if [ $? -ne 0 ]; then
		return 1
	fi

	cd ${srctree}

	if [ "${arch}" == "x86" ] || [ "${arch}" == "x86_64" ]; then
		kabi_file="dist/kabi/Module.kabi_x86_64"
	elif [ "${arch}" == "arm64" ]; then
		kabi_file="dist/kabi/Module.kabi_aarch64"
	fi

	if [ "${type}" == "create" ]; then
		if [ -s ${kabi_file} ]; then
			printf "${RED}${kabi_file} is exist${END}\n"
			return 1
		fi
	else
		if [ ! -s ${kabi_file} ]; then
			printf "${RED}get kabi file failed${END}\n"
			return 1
		fi
	fi

	echo "type: ${type}"
	echo "arch: ${arch}"
	echo "machine: ${machine}"
	echo "kabi_file: ${kabi_file}"

	compile_kernel ${machine} ${arch}
	if [ $? -ne 0 ]; then
		return 1
	fi

	if [ "${type}" == "check" ]; then
		check_kabi ${kabi_file}
		if [ $? -ne 0 ]; then
			return 1
		fi
	elif [ "${type}" == "update" ]; then
		update_kabi ${kabi_file}
		if [ $? -ne 0 ]; then
			return 1
		fi
	elif [ "${type}" == "create" ]; then
		create_kabi ${kabi_file}
		if [ $? -ne 0 ]; then
			return 1
		fi
	fi

	return 0
}

main $@
exit $?
