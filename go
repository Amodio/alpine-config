#!/bin/sh
# Boot from an Alpine ISO installation and run these commands as root:
# setup-keymap fr fr
# setup-interfaces
# service networking start
# wget boscq.fr/go
# vi go            # Optional: if you wanna change the user cfg, see below.
# sh go

START_TIME=$(date +%s)

# TODO https://wiki.alpinelinux.org/wiki/Wayland
# Bugs: `uname -i kidi`=unknown, `grep hostname /etc/conf.d/hostname`

# https://wiki.alpinelinux.org/wiki/Install_to_disk
# https://wiki.alpinelinux.org/wiki/Alpine_newbie_apk_packages
# https://wiki.alpinelinux.org/wiki/Alpine_Linux_Init_System
# https://wiki.alpinelinux.org/wiki/Tutorials_and_Howtos
# https://wiki.alpinelinux.org/wiki/Installation
# https://wiki.alpinelinux.org/wiki/Configure_Networking

# https://wiki.alpinelinux.org/wiki/Configure_a_Wireguard_interface_(wg)
# https://wiki.alpinelinux.org/wiki/Sound_Setup
# https://wiki.alpinelinux.org/wiki/Printer_Setup

# https://wiki.alpinelinux.org/wiki/Install_Alpine_on_VirtualBox

# https://wiki.alpinelinux.org/wiki/Enable_Community_Repository

####################### START OF THE USER CONFIGURATION #######################
_IFACE_='eth0'		# Network interface
_USERNAME_='user'
_HOSTNAME_='alpi'
_DOMAIN_='lan' 		# If left empty, will be prompted at setup-disk
_PROXY_='none' 		# If left empty, will be prompted at setup-disk
_APKREP_='f'   		# Use the fastest repository
_APKREP_='28'  		# Comment this line. (should be mirrors.ircam.fr)

_USERNAME_='da'     # Comment this line.
_DOMAIN_='boscq.fr' # Comment this line.

DiskPath='' 		# You should directly set your disk device

# Advanced variables
DiskEFIPath=''
DiskLVMPath=''

# TODO: Remove me
#iface eth0 inet static
#        address 192.168.1.3/24
#        gateway 192.168.1.1
#######################  END  OF THE USER CONFIGURATION #######################

if [ -z "$DiskPath" ]; then
	if [ $(ls /dev/nvme0n? /dev/sd? 2>/dev/null | wc -l) -eq 1 ]; then
        DiskPath="$(ls /dev/nvme0n? /dev/sd? 2>/dev/null)"
	else
        ls /dev/nvme0n? /dev/sd? 2>/dev/null | nl
        echo -n 'Which disk do you wanna use? '
        read DiskPath
        if [ $DiskPath -gt $(ls /dev/nvme0n? /dev/sd? 2>/dev/null | wc -l) ]; then
            DiskPath="$(ls /dev/nvme0n? /dev/sd? 2>/dev/null | head -1 | tail -1)"
        else
            DiskPath="$(ls /dev/nvme0n? /dev/sd? 2>/dev/null | head -n "$DiskPath" | tail -1)"
        fi
    fi
fi
if [ -z "$DiskPath" ]; then
    echo 'ERROR: no disk found.' >&2
    exit 1
fi
if [ -z "$DiskEFIPath" -o -z "$DiskLVMPath" ]; then
    echo "$DiskPath" | grep -q nvme
    if [ $? -eq 0 ]; then
        DiskEFIPath="${DiskPath}p1"
        DiskLVMPath="${DiskPath}p2"
    else
        DiskEFIPath="${DiskPath}1"
        DiskLVMPath="${DiskPath}2"
    fi
fi
fdisk -l
echo "Writing to $DiskPath disk."
echo "DiskEFIPath: $DiskEFIPath"
echo "DiskLVMPath: $DiskLVMPath"
echo -n 'Continue? [y/N]: '
read pause
if [ "$pause" != "y" ]; then
    echo 'Exiting.' >&2
    exit 1
fi

setup-keymap fr fr-latin9
setup-hostname -n "${_HOSTNAME_}"
/etc/init.d/hostname --quiet restart
setup-dns -d "${_DOMAIN_}" -n 9.9.9.9 -n 1.1.1.1
echo 'nameserver 2620:fe::fe' >> /etc/resolv.conf
echo 'nameserver 2606:4700:4700::1111' >> /etc/resolv.conf
#echo "iface ${_IFACE_} inet6 auto" >> /etc/network/interfaces
apk add tzdata tzdata-doc
setup-timezone -z Europe/Paris
setup-proxy "${_PROXY_}"
#rc-update add networking boot
#rc-update add urandom boot
#rc-update add acpid default
#rc-service acpid start
echo "${_APKREP_}" | setup-apkrepos > /dev/null
sed -i 's/^#http/http/' /etc/apk/repositories # Use all the (edge) repositories
apk update
echo 'no' | setup-sshd -c openssh # Disallow root login in opensshd
setup-ntp -c busybox
apk upgrade
apk add iptables ip6tables iptables-doc haveged grub grub-efi efibootmgr doas doas-sudo-shim vim bash lvm2 cryptsetup e2fsprogs dosfstools coreutils util-linux os-prober
if [ $? -ne 0 ]; then
    echo 'ERROR: Cannot install some basic tools. Please check your connectivity.' >&2
    exit 1
fi
apk del syslinux # Make 100% sure to use grub EFI bootloader instead of syslinux
# IPTables: Start ip[6]tables along with the OS
rc-update add iptables
rc-update add ip6tables
# IPTables: Set ip[6]tables rules and save them
iptables -I INPUT -i lo -j ACCEPT
iptables -A INPUT -p tcp -i "${_IFACE_}" --dport 22222 -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
iptables -A INPUT  -p icmp --icmp-type echo-reply   -j ACCEPT
iptables -P INPUT DROP
/etc/init.d/iptables save
ip6tables -I INPUT -i lo -j ACCEPT
ip6tables -A INPUT -p tcp -i "${_IFACE_}" --dport 22222 -j ACCEPT
ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT
ip6tables -A OUTPUT -p icmpv6 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
ip6tables -A INPUT  -p icmpv6 -j ACCEPT
ip6tables -P INPUT DROP
/etc/init.d/ip6tables save

echo
fdisk -l "$DiskPath"
lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINT "$DiskPath"
echo "WARNING: DISK $DiskPath WILL BE FULLY ERASED. PRESS ENTER TO CONTINUE."
read pause
wipefs -a -f "$DiskPath"
# Create two partitions: 50M partition for /boot/efi and the rest for a LGVM
fdisk "$DiskPath" << __EOF__
g
n


+50M
t
1
n



w
__EOF__

# Prepare (format) the partitions
mkfs.fat -F32 -n EFI "$DiskEFIPath"
#haveged -n 0 | dd of="$DiskLVMPath" # Optional: Overwrite LUKS Partition with Random Data
mkdir -m0700 /run/cryptsetup
#cryptsetup -q -v -c serpent-xts-plain64 -s 512 --hash whirlpool --iter-time 5000 --use-random luksFormat "$DiskLVMPath"
# Forced to use LUKS 1 for GRUB2
cryptsetup -q -v --type luks1 luksFormat "$DiskLVMPath"
cryptsetup luksOpen "$DiskLVMPath" lvmcrypt
rc-update add lvm # Start LVM during boot
pvcreate /dev/mapper/lvmcrypt
vgcreate vg0 /dev/mapper/lvmcrypt
lvcreate -L 8G -n root vg0       # 8 GiB for /
lvcreate -l 100%FREE -n home vg0 # rest  for /home
mkfs.ext4 -L root /dev/vg0/root
mkfs.ext4 -L home /dev/vg0/home

# Mount the system from disk onto /mnt
vgchange -ay
mount -t ext4 /dev/vg0/root /mnt/
mkdir -p /mnt/boot/efi; mount -t vfat "$DiskEFIPath" /mnt/boot/efi
mkdir -p /mnt/home; mount -t ext4 /dev/vg0/home /mnt/home

# Install Alpine
setup-disk -s 0 -m sys /mnt

echo "lvmcrypt UUID=$(blkid -s UUID -o value ${DiskLVMPath}) none luks" > /mnt/etc/crypttab
echo 'GRUB_DISABLE_OS_PROBER=false
GRUB_DEFAULT=saved
GRUB_SAVEDEFAULT=true
GRUB_ENABLE_CRYPTODISK=y
GRUB_PRELOAD_MODULES="luks cryptodisk part_gpt lvm disk diskfilter"' >> /mnt/etc/default/grub
sed -i 's/GRUB_TIMEOUT=2$/GRUB_TIMEOUT=0/' /mnt/etc/default/grub
sed -i 's#cryptdm=root#cryptdm=lvmcrypt cryptkey#' /mnt/etc/default/grub
#sed -i 's#cryptdm=root#cryptdm=lvmcrypt cryptkey=rootfs:/crypto_keyfile.bin#' /mnt/etc/default/grub

#echo "GRUB_ENABLE_CRYPTODISK=y
#GRUB_CMDLINE_LINUX_DEFAULT=\"cryptroot=UUID=$(blkid -s UUID -o value ${DiskLVMPath}) cryptdm=lvmcrypt\"" >> /mnt/etc/default/grub

# ViM
ln -sf /usr/bin/vim /mnt/usr/bin/vi
# ViM: configure
grep -q 'set tabstop' /mnt/etc/vim/vimrc
if [ $? -ne 0 ]; then
    echo 'set tabstop=4' >> /mnt/etc/vim/vimrc
fi
grep -q 'set expandtab' /mnt/etc/vim/vimrc
if [ $? -ne 0 ]; then
    echo 'set expandtab' >> /mnt/etc/vim/vimrc
fi
grep -q 'set nobk' /mnt/etc/vim/vimrc
if [ $? -ne 0 ]; then
    echo 'set nobk' >> /mnt/etc/vim/vimrc
fi

# Set Bash as our default shell
ln -sf /bin/bash /mnt/bin/sh
sed -i 's#/bin/ash$#/bin/bash#' /mnt/etc/passwd

# Auto-login
grep -q agetty /mnt/etc/inittab
if [ $? -ne 0 ]; then
    sed -i 's/^tty/#tty/' /mnt/etc/inittab
    sed -i 's/^#tty1\([^g]*\)getty\(.*\)$/tty1\1agetty -a '"${_USERNAME_}"' -J\2/' /mnt/etc/inittab
    # DEBUG: root session opened on tty2
    sed -i 's/^#tty2\([^g]*\)getty\(.*\)$/tty2\1agetty -a root -J\2/' /mnt/etc/inittab
fi

# MOTD
echo "Welcome to Alpine!" > /mnt/etc/motd

# Sudoers: add our user
grep -q "'^${_USERNAME_}'" /mnt/etc/sudoers
if [ $? -ne 0 ]; then
    echo "${_USERNAME_} ALL=(ALL:ALL) NOPASSWD: ALL" >> /mnt/etc/sudoers
fi

# SSHd hardening
# \ SSHd: Connection banner
if [ ! -f '/mnt/etc/sshd_banner' ]; then
    echo '################################################################################
# Authorized Use Only. Transactions may be monitored. By continuing past this  #
# point, you expressly consent to this monitoring.                             #
################################################################################' > /mnt/etc/sshd_banner
fi
# \ SSHd: Configure
sed -i 's/^#Port 22$/Port 22222/' /mnt/etc/ssh/sshd_config
sed -i 's/^#Banner none$/Banner \/etc\/sshd_banner/' /mnt/etc/ssh/sshd_config
sed -i 's/^#PasswordAuthentication yes$/PasswordAuthentication no/' /mnt/etc/ssh/sshd_config

# Env vars
grep -q LESSHISTFILE /mnt/etc/profile
if [ $? -ne 0 ]; then
    sed -i "1 i\export LESSHISTFILE='/dev/null'" /mnt/etc/profile
fi

# Aliases
if [ ! -f '/mnt/etc/profile.d/aliases.sh' ]; then
    echo "alias ls='ls --color'
alias l='ls'
alias ll='ls -la'

alias grep='grep --color'

alias apk_='sudo apk update; sudo apk upgrade'" > /mnt/etc/profile.d/aliases.sh
fi

# Colored prompt
if [ -f '/mnt/etc/profile.d/color_prompt' ]; then
    mv -f /mnt/etc/profile.d/color_prompt /mnt/etc/profile.d/color_prompt.sh
    sed -i 's#\\h #\\A #' /mnt/etc/profile.d/color_prompt.sh
fi

# Crypto keyfile (auto-unlock LVM volumes)
dd bs=512 count=4 if=/dev/urandom of=/mnt/crypto_keyfile.bin iflag=fullblock
chmod 000 /mnt/crypto_keyfile.bin
cryptsetup luksAddKey "$DiskLVMPath" /mnt/crypto_keyfile.bin
echo "erf?"
read erf
echo '#!/bin/bash
_USERNAME_='"'${_USERNAME_}'" > /mnt/root/install.sh
cat << '__EOF__' >> /mnt/root/install.sh

START_TIME=$(date +%s)

# Install some basic cmds with documentation + misc:
# - bind-tools: host + dig + ...
# - Sniffing tools
# - S.M.A.R.T. tools like smartctl
# - Nmap network port scanner
# - Archives
# - Web browser
# - Music Player console Client
# - Music Player Daemon
# - Video players
# - FTP client
# - IRC client
# - SCREEN TTY utility
# - PDF reader
# - Debugging
# - Debugger + advanced memory debugger
# - Console tools for image manipulation
# - Distributed version-control system
# - Encryption partition tools doc
# - Docker
# - Wireguard
# XXX TODO - Yubikey + unrar(-doc)
apk add procps procps-doc coreutils-doc gawk gawk-doc man-db man-pages lsof lsof-doc less less-doc grep grep-doc curl curl-doc alpine-sdk iptables-doc sudo-doc vim-doc bash-doc bash-completion util-linux-doc util-linux-bash-completion openrc-bash-completion bind-tools ldns-doc tcpdump tcpdump-doc wireshark smartmontools smartmontools-doc nmap nmap-doc p7zip p7zip-doc chromium mpc mpc-doc mpc-bash-completion mpd mpd-doc mplayer mplayer-doc vlc vlc-doc lftp lftp-doc irssi irssi-doc screen screen-doc evince evince-doc strace strace-doc ltrace ltrace-doc gdb gdb-doc valgrind valgrind-doc graphicsmagick graphicsmagick-doc git git-doc git-bash-completion cryptsetup-doc docker docker-doc docker-compose docker-bash-completion docker-compose-bash-completion wireguard-tools wireguard-tools-doc wireguard-tools-bash-completion
# Wireguard: ifupdown-ng-wireguard TODO https://wiki.alpinelinux.org/wiki/Configure_a_Wireguard_interface_(wg)

# Create the user
id "${_USERNAME_}" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    adduser -D -g '' -G users -s /bin/bash "${_USERNAME_}"
    choose() { echo ${1:RANDOM%${#1}:1} $RANDOM; }
      PASSWORD="$({ choose '!@#$%^\&'
      choose '0123456789'
      choose 'abcdefghijklmnopqrstuvwxyz'
      choose 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
      for i in $( seq 1 $(( 20 + RANDOM % 4 )) ); do
        choose '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
      done
     } | sort -R | awk '{printf "%s",$1}')" # Kudos to https://stackoverflow.com/a/26665585
    echo "${_USERNAME_}:$PASSWORD" | chpasswd
    echo "$PASSWORD" > "/home/${_USERNAME_}/.pw"
    chown "${_USERNAME_}:users" "/home/${_USERNAME_}/.pw"
    chmod 400 "/home/${_USERNAME_}/.pw"
else
    echo 'WARNING: this user already exists!' >&2
fi
addgroup "$_USERNAME_" wireshark

dmesg | grep -q VBOX
if [ $? -eq 0 ]; then
    apk add virtualbox-guest-additions virtualbox-guest-additions-x11 virtualbox-guest-additions-openrc xf86-video-vboxvideo xf86-video-vboxvideo-doc xf86-video-vmware xf86-video-vmware-doc
    rc-update add virtualbox-guest-additions
fi

# Install Openbox (GUI)
setup-xorg-base openbox openbox-doc py3-xdg conky conky-doc feh feh-doc thunar thunar-doc tint2 tint2-doc wbar wbar-doc dbus dbus-doc rxvt-unicode rxvt-unicode-doc xf86-video-fbdev xf86-video-vesa xf86-video-vesa-doc xf86-video-nouveau xf86-video-nouveau-doc
#rc-service dbus start
rc-update add dbus
apk update; apk upgrade

# Regenerate an initramfs image with the keymap&cryptsetup modules
sed -i 's/"$/ keymap nvme"/' /etc/mkinitfs/mkinitfs.conf
mkinitfs -c /etc/mkinitfs/mkinitfs.conf $(ls /lib/modules/)

# Grub
grub-install --target=x86_64-efi --efi-directory=/boot/efi
grub-mkconfig -o /boot/grub/grub.cfg

echo -n '%------------------------+ Pkgs install done in '
printf "%02ds. +-------------------------%%\n" $(expr $(date +%s) - $START_TIME)

# Remove the installation file
rm -f /root/install.sh
__EOF__
chmod +x /mnt/root/install.sh

# Chroot into the system to execute the previous/install script
mount -t proc /proc /mnt/proc
mount --rbind /dev /mnt/dev
mount --make-rslave /mnt/dev
mount --rbind /sys /mnt/sys
chroot /mnt /root/install.sh
if [ ! -f "/mnt/home/${_USERNAME_}/.xinitrc" ]; then
    echo "export LANG='fr_FR.UTF-8'
export LC_ALL='fr_FR.UTF-8'
exec openbox-session" > "/mnt/home/${_USERNAME_}/.xinitrc"
fi

if [ ! -f "/mnt/home/${_USERNAME_}/.profile" ]; then
    echo 'if [ -z "$DISPLAY" -a "$(tty)" == /dev/tty1 ]; then
    startx
fi' > "/mnt/home/${_USERNAME_}/.profile"
fi
# User: Install our SSH authorized key
#if [ ! -d "/mnt/home/{_USERNAME_}/.ssh" -a -f '/mnt/root/.ssh/authorized_keys' ]; then
#    mkdir -p "/mnt/home/{_USERNAME_}/.ssh"
#    cp -f /mnt/root/.ssh/authorized_keys "/mnt/home/{_USERNAME_}/.ssh/authorized_keys"
#    chown "${_USERNAME_}:users" -R "/mnt/home/{_USERNAME_}/.ssh"
#fi
echo -n '%-------------------------+ Installation took '
printf "%02dm%02ds. +------------------------%%\n" $(expr \( $(date +%s) - $START_TIME \) \/ 60) $(expr \( $(date +%s) - $START_TIME \) % 60)
umount -R /mnt/proc /mnt/dev /mnt/sys /mnt/boot/efi /mnt/home
echo '%--------------------------+ PRESS ENTER TO REBOOT +---------------------------%'
read pause

# Unmount the disk and reboot
umount /mnt
vgchange -an
cryptsetup luksClose lvmcrypt
# Eject the media and reboot
service modloop stop
eject
reboot