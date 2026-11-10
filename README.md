# alpine-config
Custom Alpine Linux ISO with automated installation and configuration, built using Alpine's `mkimage.sh` infrastructure.

## Features
  * Alpine Linux desktop taking less than 4GB
  * labwc (successor of `openbox`) on Wayland
  * /boot unencrypted + encrypted LFS (/ & /home) -> selected disk is wiped
  * BIOS/UEFI compatible

## Installation
  1) Download [alpine-amodio-edge-x86_64.iso](https://github.com/Amodio/alpine-config/releases/latest/download/amodio.iso).
  2) Boot on it in a VM or with an USB disk (you may use [Ventoy](https://www.ventoy.net/en/download.html)).
  3) Answer a few questions for configuration, wait 2 minutes for the installation and press enter to reboot, enjoy!

## For developpers
### Prerequisites
```bash
apk add abuild alpine-conf syslinux xorriso squashfs-tools grub mtools

abuild-keygen -a

git clone --depth=1 https://github.com/alpinelinux/aports.git

ln -s "$(pwd)/genapkovl-amodio.sh" aports/scripts/
ln -s "$(pwd)/mkimg.amodio.sh" aports/scripts/
ln -s "$(pwd)/autoinstall.sh" aports/scripts/
ln -s "$(pwd)/local_files/" aports/scripts/
```

### Generate the ISO
```bash
./aports/scripts/mkimage.sh --tag edge --repository https://dl-cdn.alpinelinux.org/alpine/edge/main --profile amodio
```
