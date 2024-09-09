#！/bin/sh
sudo ip link set ens33 xdp off #Replace ens33 with your interface
sudo clang -O2 -Wall -target bpf -c FragEva6-Guard.c -o FragEva6-Guard.o
sudo ip link set dev ens33 xdp obj FragEva6-Guard.o sec xdp
