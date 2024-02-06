# linux source + BPF headers preparation

## generate bpf_helpers.h, bpf_helper_defs.h, bpf_endian.h

```bash
apt get linux-source
cp /usr/src/linux-source-X.X.X/linux-source-X.X.X.tar.bz2 .
tar -xvf linux-source-X.X.X.tar.bz2
mv linux-source-X.X.X linux-source
cd linux-source
make -C tools/lib/bpf
```
## Copy into the include directory

```bash
mkdir -p include
cp linux-source/tools/lib/bpf/bpf_endian.h \
   linux-source/tools/lib/bpf/bpf_helper_defs.h \
   linux-source/tools/lib/bpf/bpf_helpers.h \
   include/
```
