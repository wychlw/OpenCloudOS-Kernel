#!/bin/bash

kernel=KERNELMODULE_REPLACE
dir=./ko_files.signed
list=./ko.location

if [ ! -d /lib/modules/$kernel/build/ ]; then
	echo "we need to install $kernel kernel devel rpm first :("
	exit 1
fi

./mlnxofedinstall --without-depcheck --skip-distro-check --distro rhel9.4 --without-fw-update --force --kernel-sources /lib/modules/$kernel/build/ --kernel $kernel
if [ $? -ne 0 ]; then
	echo "mlnxofedinstall failed :("
	exit 1
fi

for line in $(cat $list)
do
	if [ -f $line ]; then
		file=$(basename $line)
		echo copying $file
		cp $dir/$file $line
		if [ $? -ne 0 ]; then
			echo "copying file failed :("
			exit 1
		fi
	fi
done

if [ ! -f /boot/initramfs-$kernel.img ]; then
	echo "initramfs does not exist :("
fi

dracut -f /boot/initramfs-$kernel.img --kver $kernel
if [ $? -ne 0 ]; then
	echo "dracut failed :("
	exit 1
fi

exit 0
