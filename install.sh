sudo make INSTALL_PATH=/mnt/testing/boot install
sudo make INSTALL_MOD_PATH=/mnt/testing/ modules_install

KERNEL_VERSION=$(make kernelrelease)

sudo chroot /mnt/testing << EOF
update-initramfs -c -k $KERNEL_VERSION
update-grub
EOF
