# eBPF-fuzzer

## Build and Test LKL

### 0) Install Prerequisites

Use the docker image with required dependencies:

```bash
docker pull nkhusain/ebpf_fuzzer
docker run -ti nkhusain/ebpf_fuzzer /bin/bash
```

or

Install in your machine directly (on Ubuntu 22.04):

```bash
sudo apt-get install -y flex bison libelf-dev python-is-python3

# Install Clang-15
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 15
```

### 1) Build LKL Kernel

If you used docker, run `docker run -ti nkhusain/ebpf_fuzzer /bin/bash`

```bash
git clone --single-branch -b dev https://github.com/ssrg-vt/ebpf-fuzzer.git
cd ebpf-fuzzer
cp lkl_ebpf_config arch/lkl/configs/defconfig
make ARCH=lkl defconfig CC=clang-15
```

### 2) Build the LKL Tools

```bash
make -C tools/lkl ARCH=lkl CC=clang-15 -j8
```

### 3) Build the Sample Program

[tools/lkl/bytecode/hello.c](tools/lkl/bytecode/hello.c)

```bash
cd tools/lkl/bytecode/
./build.sh hello
```

#### Run eBPF Fuzzer

```bash
cd tools/lkl/bytecode/
./ebpf_gen.py
```

```

```
