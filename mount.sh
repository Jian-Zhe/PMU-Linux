sudo mount /dev/sda4 /mnt/testing
sudo mount --bind /dev /mnt/testing/dev
sudo mount --bind /proc /mnt/testing/proc
sudo mount --bind /sys /mnt/testing/sys
sudo mount --bind /dev/pts /mnt/testing/dev/pts

