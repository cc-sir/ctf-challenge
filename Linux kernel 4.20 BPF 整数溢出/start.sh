#!/bin/sh
qemu-system-x86_64 \
-m 2048 -smp 1 -net nic,model=e1000 \
-display none -serial stdio -no-reboot \
-cpu kvm64,+smep \
-initrd ./bpf.cpio \
-kernel ./bzImage \
-gdb tcp::1234 \
-append "root=/dev/sda console=ttyS0 earlyprintk=serial oops=panic panic_on_warn=0 nokaslr ftrace_dump_on_oops=orig_cpu rodata=n vsyscall=native net.ifnames=0 biosdevname=0 "
