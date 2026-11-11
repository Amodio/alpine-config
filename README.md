# alpine-config
Custom Alpine Linux ISO with automated installation and configuration, built using Alpine's `mkimage.sh`.

## Features
  * Alpine Linux desktop taking less than 4GB
  * `labwc` (successor of `openbox`) on Wayland
  * FDE: one encrypted rootfs (+ EFI partition for UEFI) -> selected disk will be wiped
  * BIOS/UEFI compatible

## Installation
  1) Download [alpine-amodio-edge-x86_64.iso](https://github.com/Amodio/alpine-config/releases/latest/download/alpine-amodio-edge-x86_64.iso).
  2) Boot on it in a VM or with an USB disk (you may use [Ventoy](https://www.ventoy.net/en/download.html)).
  3) Answer a few questions for configuration, wait 2 minutes for the installation and press enter to reboot, enjoy!

## Note
It is recommended to use UEFI as 32-bit BIOS GRUB implementation is doing the PBKDF2 computation less efficiently than the x86_64 EFI implementation (takes double the time to boot!).

## For developpers
### Prerequisites
```bash
apk add abuild alpine-conf syslinux xorriso squashfs-tools grub mtools

git clone --depth=1 https://github.com/alpinelinux/aports.git

ln -s "$(pwd)/genapkovl-amodio.sh" aports/scripts/
ln -s "$(pwd)/mkimg.amodio.sh" aports/scripts/
ln -s "$(pwd)/autoinstall.sh" aports/scripts/
ln -s "$(pwd)/local_files/" aports/scripts/

abuild-keygen -a -i
```

### Generate the ISO
```bash
./aports/scripts/mkimage.sh --tag edge --repository https://dl-cdn.alpinelinux.org/alpine/edge/main --profile amodio
```
