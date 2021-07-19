# Basic sample binaries

## Toolchain setup

Follow the instructions here:
https://github.com/riscv/riscv-gnu-toolchain

(basically, clone the repo and execute:)
```
./configure --prefix=/ssd/toolchain/riscv64i --with-arch=rv64i
make -j 4
```

## Building

```
CC=/ssd/toolchain/riscv64i/bin/riscv64-unknown-elf-gcc make 
```

(The binaries are pretty small, so I've added them to git)

## Running:

```
qemu-riscv64 hello_world
```

## Crosscompiling

### Autotools

```
autoreconf -i
CC=/path/to/riscv64-unknown-linux-gnu-gcc ./configure --host=x86_64
make
```
