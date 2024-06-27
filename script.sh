make LLVM=1 -j12 
sudo make LLVM=1 modules_install INSTALL_MOD_PATH=../busybox/_install
cd ../busybox/_install
find . | cpio -H newc -o | gzip > ../ramdisk.img
cd ../../linux
qemu-system-x86_64 -nographic -kernel vmlinux -initrd ../busybox/ramdisk.img -nic user,model=rtl8139,hostfwd=tcp::5555-:23,hostfwd=tcp::5556-:8080
