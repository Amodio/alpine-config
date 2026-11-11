#!/bin/sh -u
#
# Copyright (c) 2026 Jacques Boscq <jacques@boscq.fr>. All rights reserved.
# This work is licensed under the terms of the MIT license.
#

START_TIME=$(date +%s) # Time the execution of this script

# Boot mode (needed early: the partition layout depends on it)
if [ -d /sys/firmware/efi ]; then
    _UEFI_=1
else
    _UEFI_=0
fi

info() {
    echo -e "\e[32m[\e[1;32m\e[1m+\e[32m]\e[0m $@"
}

warn() {
    echo -e "\e[32m[\e[1;33m\e[1m!\e[32m]\e[0m $@" > /dev/stderr
}

error() {
    echo -e "\e[32m[\e[31m\e[1m!\e[32m]\e[0m $@" > /dev/stderr
    exit 1
}

# _get_iface_choice: Return user's choice of the internet network device,
#                    $1 is `$ifaces`, $2 is max(n).
_get_iface_choice() {
    while true; do
        local n
        echo -e "     #\tInterface"
        echo "$1" | nl
        read -p "Please select the internet interface (1-$2): " n
        if [ "$n" -gt 0 -a "$n" -le "$2" ]; then
            return "$n"
        fi
        warn 'Invalid choice'
    done
}

#select_iface: Set `$NetIface` which is the internet network interface name.
select_iface(){
    local ifaces="$(ls /sys/class/net/ | egrep -v '^lo$' 2>/dev/null)"
    if [ -z "$ifaces" ]; then
        error 'Cannot find any network interface'
    fi
    local n_ifaces=$(echo "$ifaces" | wc -l)
    if [ $n_ifaces -eq 1 ]; then
        NetIface="$ifaces"
    else
        _get_iface_choice "$ifaces" "$n_ifaces"
        NetIface="$(echo "$ifaces" | sed -n ${?}p)"
    fi
}

# _prettify_disk_list: Append disk size&name to $1 which is the `$disks` list.
_prettify_disk_list() {
    for line in $1; do
        local disk_name=$(echo "$line" | sed 's#^/dev/##')
        local size=$(cat "/sys/block/$disk_name/size" 2>/dev/null)
        local size=$(expr $size \* 512 / 1024 / 1024 / 1024 2>/dev/null)
        local name=$(cat "/sys/block/$disk_name/device/model" 2>/dev/null)
        echo -e "$line\t$size GB\t\t$name"
    done
}

# _get_disk_choice: Return user's choice about what disk to use,
#                   $1 is `$disks`, $2 is max(n).
_get_disk_choice() {
    while true; do
        local n
        echo -e "     #\tDevice\t\tSize\t\tName"
        echo "$1" | nl
        read -p "Please select the disk to use (1-$2): " n
        if [ "$n" -gt 0 -a "$n" -le "$2" ]; then
            return "$n"
        fi
        warn 'Invalid choice'
    done
}

# select_disk: Set `$DiskPath` which is the drive to write to.
#                  `DiskBootPath` ESP partition (UEFI only, empty on BIOS)
#                  `DiskRootPath` encrypted partition holding / and /boot
select_disk() {
    local disks="$(ls /dev/nvme?n? /dev/sd? /dev/vd? 2>/dev/null)"
    if [ -z "$disks" ]; then
        error 'Cannot find any disk'
    fi
    local n_disks=$(echo "$disks" | wc -l)
    if [ $n_disks -eq 1 ]; then
        DiskPath="$disks"
    else
        local disks=$(_prettify_disk_list "$disks")
        _get_disk_choice "$disks" "$n_disks"
        DiskPath="$(echo "$disks" | sed -n ${?}p | awk '{print $1}')"
    fi
    local P
    case "$DiskPath" in
        *nvme*) P="${DiskPath}p" ;;
        *)      P="$DiskPath" ;;
    esac
    if [ $_UEFI_ -eq 1 ]; then
        DiskBootPath="${P}1"   # ESP (unencrypted, only holds the GRUB EFI binary)
        DiskRootPath="${P}2"   # LUKS: / and /boot
    else
        DiskBootPath=''        # No boot partition on BIOS
        DiskRootPath="${P}1"   # LUKS: / and /boot
    fi
}

# setup_iptables: Set ip[6]tables rules, allow SSHd and pings.
setup_iptables() {
    # IPTables: Start ip[6]tables along with the OS
    rc-update add iptables
    rc-update add ip6tables
    # IPTables: Set ip[6]tables rules and save them
    iptables -I INPUT -i lo -j ACCEPT
    iptables -A INPUT -p tcp -i "$NetIface" --dport 22222 -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT
    iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
    iptables -A INPUT  -p icmp --icmp-type echo-reply   -j ACCEPT
    iptables -P INPUT DROP
    rc-service iptables save
    ip6tables -I INPUT -i lo -j ACCEPT
    ip6tables -A INPUT -p tcp -i "$NetIface" --dport 22222 -j ACCEPT
    ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT
    ip6tables -A OUTPUT -p icmpv6 -m conntrack \
        --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
    ip6tables -A INPUT  -p icmpv6 -j ACCEPT
    ip6tables -P INPUT DROP
    rc-service ip6tables save
}

# ask_passphrase: Ask the LUKS passphrase (twice) and store it in `$LuksPass`.
#                 It is asked only once for the whole install: it is piped to
#                 every cryptsetup call below.
ask_passphrase() {
    local p1 p2 saved_keymaps saved_keymap

    # Preserve the keymap selected earlier, including its boot configuration.
    if [ ! -f /etc/conf.d/loadkmap ]; then
        error 'Cannot find the current keymap configuration'
    fi
    saved_keymaps=$(cat /etc/conf.d/loadkmap)
    . /etc/conf.d/loadkmap
    saved_keymap="${KEYMAP:-}"
    if [ -z "$saved_keymap" ] || [ ! -f "$saved_keymap" ]; then
        error 'Cannot determine the current keymap file'
    fi

    info 'GRUB reads the passphrase with a US (QWERTY) keymap at boot!'
    info 'Temporarily switching to the US keymap for the LUKS passphrase'
    if ! setup-keymap us us; then
        error 'Cannot switch to the US keymap'
    fi

    while true; do
        read -s -p 'LUKS passphrase: ' p1; echo
        read -s -p 'LUKS passphrase (again): ' p2; echo
        if [ -z "$p1" ]; then
            warn 'Empty passphrase'
        elif [ "$p1" != "$p2" ]; then
            warn 'Passphrases do not match'
        else
            LuksPass="$p1"
            break
        fi
    done

    # Restore the saved configuration and apply it to the live console.
    printf '%s\n' "$saved_keymaps" > /etc/conf.d/loadkmap
    if ! zcat "$saved_keymap" | loadkmap; then
        error 'Cannot restore the original keymap'
    fi
    info 'Restored the original keymap'
}

# setup_partitions: Write partitions to disk, format and mount volumes.
setup_partitions() {
    local pause
    fdisk -l "$DiskPath"
    lsblk -o NAME,SIZE,TYPE,MOUNTPOINTS "$DiskPath"
    warn "/!\\ DISK $DiskPath WILL BE FULLY ERASED. PRESS ENTER TO CONTINUE. /!\\"
    read pause
    ask_passphrase
    info 'Fast-wiping the disk'
    wipefs -qaf "$DiskPath"
    if [ $_UEFI_ -eq 1 ]; then
        info 'Creating two partitions: 256M ESP and the rest for an encrypted rootfs'
        parted -s "$DiskPath" mklabel gpt \
            mkpart ESP fat32 1MiB 257MiB set 1 esp on \
            mkpart primary 257MiB 100%
    else
        info 'Creating one partition: an encrypted rootfs'
        parted -s "$DiskPath" mklabel msdos mkpart primary 1MiB 100%
    fi
    sync
    partprobe "$DiskPath" # force the kernel to re-scan the disk for partitions
    mdev -s # Force device node creation
    if [ ! -e "$DiskRootPath" ]; then
        error 'There was an error creating the devices...'
    fi
    if [ $_UEFI_ -eq 1 -a ! -e "$DiskBootPath" ]; then
        error 'There was an error creating the devices...'
    fi
    info 'Formatting the partitions'
    if [ $_UEFI_ -eq 1 ]; then
        mkfs.fat -F32 -n EFI "$DiskBootPath" > /dev/null
    fi
    #haveged -n 0 | dd of="$DiskRootPath" # Optional: Fill LUKS Partition with random data
    info 'Configuring LUKS2 encryption'
    printf '%s' "$LuksPass" | cryptsetup --batch-mode luksFormat --type luks2 \
        --cipher aes-xts-plain64 --key-size 512 \
        --pbkdf argon2id --iter-time 1000 --key-file - "$DiskRootPath"
    # Disable Discard/TRIM and dm-crypt workqueues.
    # https://wiki.archlinux.org/title/Dm-crypt/Specialties#Discard/TRIM_support_for_solid_state_drives_(SSD)
    # https://wiki.archlinux.org/title/Dm-crypt/Specialties#Disable_workqueue_for_increased_solid_state_drive_(SSD)_performance
    printf '%s' "$LuksPass" | cryptsetup open --perf-no_read_workqueue \
        --perf-no_write_workqueue --persistent --key-file - \
        "$DiskRootPath" cryptroot
    mkfs.ext4 -L alpine-root /dev/mapper/cryptroot

    # Mount the single encrypted filesystem as / (+ /boot inside it)
    mount -t ext4 /dev/mapper/cryptroot /mnt/
    mkdir -p /mnt/boot/
    if [ $_UEFI_ -eq 1 ]; then
        mkdir -p /mnt/boot/efi/
        mount -t vfat "$DiskBootPath" /mnt/boot/efi/
    fi
}

# setup_keyfile: Create a random keyfile, enrol it in a second LUKS keyslot and
#                embed it in the initramfs (/crypto_keyfile.bin, see the
#                `cryptkey` mkinitfs feature below). GRUB asks the passphrase
#                once; the initramfs then unlocks the root with the keyfile
#                instead of asking again. This is safe because the initramfs
#                lives in the encrypted /boot (and is chmod 600).
setup_keyfile() {
    info 'Creating the initramfs keyfile'
    dd if=/dev/urandom of=/mnt/crypto_keyfile.bin bs=512 count=4 2>/dev/null
    chmod 000 /mnt/crypto_keyfile.bin
    # The keyfile is random (high entropy): a fast PBKDF2 slot is fine, and
    # PBKDF2 keeps the header GRUB-friendly.
    printf '%s' "$LuksPass" | cryptsetup luksAddKey --key-file - \
        --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
        "$DiskRootPath" /mnt/crypto_keyfile.bin
    if [ $? -ne 0 ]; then
        error 'Cannot add the keyfile to the LUKS header'
    fi
    unset LuksPass
}

#create_user: Create the user.
create_user() {
    useradd -m -s /bin/bash -G users "$_USERNAME_"
    if [ $? -ne 0 ]; then
        error 'Cannot create the user'
    fi
}

# setup_user: Assign a password to the user and store it in `~/.pw`,
#             user can use sudo without any password. Add user to his groups.
setup_user() {
    local g
    local PASSWORD="$(pwgen --secure 32 1)"
    echo "${_USERNAME_}:$PASSWORD" | chpasswd
    echo "$PASSWORD" > "/home/${_USERNAME_}/.pw"
    chown "${_USERNAME_}:users" "/home/${_USERNAME_}/.pw"
    chmod 400 "/home/${_USERNAME_}/.pw"
    # doas/sudo: no password needed
    echo "permit nopass $_USERNAME_" >> /etc/doas.d/doas.conf
    for g in abuild audio docker kvm libvirt qemu pcscd plugdev seat; do
        addgroup "$_USERNAME_" "$g"
    done
}

# Steps: https://wiki.alpinelinux.org/wiki/Alpine_setup_scripts#setup-alpine

# 1. Keymap
info 'Setting keymap (fr fr-latin9)'
setup-keymap fr fr-latin9
read -p "Change keymap? [n] " n
if [ "$n" = 'y' -o "$n" = 'yes' ]; then
    setup-keymap
fi

# Disk partitions
info 'Determining the disk to use...'
select_disk
info "-> $DiskPath: encrypted / and /boot @ $DiskRootPath (ESP: ${DiskBootPath:-none})"

# Username
_USERNAME_='user'
read -p "Username? [$_USERNAME_] " n
if [ -n "$n" ]; then
    _USERNAME_="$n"
fi

# 2&8. Hostname
_HOSTNAME_='alpi'
read -p "Hostname? [$_HOSTNAME_] " n
if [ -n "$n" ]; then
    _HOSTNAME_="$n"
fi
info "Setting hostname ($_HOSTNAME_)"
setup-hostname -n "$_HOSTNAME_"
hostname -F /etc/hostname

# 3&4. Net interface
info 'Determining the internet network interface...'
select_iface
info "-> $NetIface"
setup-interfaces -r
read -p "Run setup-interfaces again (to use static IP instead of DHCP)? [n] " n
if [ "$n" = 'y' -o "$n" = 'yes' ]; then
    setup-interfaces -r
fi

# 5. DNS
info 'Setting DNS (Cloudflare & DNS4EU)'
setup-dns '1.1.1.1' '86.54.11.100' '2606:4700:4700::1111' '2a13:1001::86:54:11:100'

# 7. Timezone
_TIMEZONE_='Europe/Paris'
info "Setting timezone ($_TIMEZONE_)"
read -p "Change timezone? [n] " n
if [ "$n" = 'y' -o "$n" = 'yes' ]; then
    setup-timezone
else
    setup-timezone -z "$_TIMEZONE_"
fi

# 9. Add services to start in OpenRC
rc-update add networking boot
rc-update add seedrng boot
rc-update add acpid default
rc-update add crond default

# 11. Proxy
_PROXY_='none' # If left empty it will be prompted at setup-disk
read -p "Proxy? [$_PROXY_] " n
if [ -n "$n" ]; then
    _PROXY_="$n"
fi
info "Setting proxy ($_PROXY_)"
setup-proxy "$_PROXY_"

# 12. APK repository mirror
read -p "Use the fastest repository (~1m30s)? [y] " n
if [ "$n" = 'n' -o "$n" = 'no' ]; then
    _APKREP_='-1' # Select the first mirror
else
    _APKREP_='-f' # Select the fastest mirror
fi
info 'Setting APK repositories (with the community repository)'
setup-apkrepos -c "$_APKREP_" # Add the community repository
if [ $? -ne 0 ]; then
    error 'Cannot select APK repository, please check your connectivity'
fi
# Add the testing repository
sed -n '/\/edge\/main$/s/main/testing/p' /etc/apk/repositories >> /etc/apk/repositories

apk update && apk add --no-cache coreutils util-linux \
                parted dosfstools e2fsprogs cryptsetup
if [ $? -ne 0 ]; then
    error 'Cannot install packages, please check your connectivity'
fi
info 'Setting disk partitions'
setup_partitions

info 'Updating & installing packages'
apk add --no-cache docs man-db man-pages                \
    bash bash-completion fuse iptables meson            \
    gcompat libstdc++ musl-locales extra-cmake-modules  \
    alpine-sdk bind-tools pciutils smartmontools upower \
    agetty findutils findutils-locate ncurses           \
    gdb ltrace strace                                   \
    command-not-found go-mtpfs libfido2 libnotify       \
    curl grep gawk less lsof procps-ng btop vim shadow  \
    doas doas-sudo-shim                                 \
    docker docker-cli-compose                           \
    python3 py3-pip                                     \
    alsaconf alsa-utils                                 \
    dbus polkit seatd                                   \
    labar labwc chayang cliphist wl-clipboard mako      \
    rofi rofi-calc rofi-emoji rofi-yubikey-oath         \
    speech-dispatcher swaylock swaybg swayidle          \
    numix-themes-openbox                                \
    simp1e-cursors sound-theme-freedesktop              \
    adwaita-icon-theme font-awesome font-dejavu         \
    font-inconsolata font-ipa font-isas-misc            \
    font-jis-misc font-mutt-misc font-noto-all          \
    font-noto-emoji font-sony-misc font-terminus        \
    font-twemoji font-vollkorn                          \
    grim slurp swappy imagemagick imv mpv vlc mpc mpd   \
    libvirt libvirt-qemu qemu-system-x86_64             \
    qemu-modules virt-manager virtiofsd                 \
    unzip 7zip                                          \
    keepassxc keepassxc-browser keepassxc-firefox-manifest\
    firefox foot git plattenalbum pwgen rclone thunar   \
    thunderbird yt-dlp zathura zathura-pdf-mupdf
# lang xwayland qemu-system-i386 ?
if [ $? -ne 0 ]; then
    error 'Cannot install packages, please check your connectivity'
fi
rc-update add alsa
rc-update add dbus
rc-update add libvirtd
rc-update add libvirt-guests
rc-update add mpd
rc-update add pcscd
rc-update add polkit
rc-update add seatd

# Install spice-vdagent if in a VM supporting spice
# XXX: Wayland not currently supported: https://gitlab.freedesktop.org/spice/linux/vd_agent/-/merge_requests/57
grep -qE '^com.redhat.spice.0|^org.qemu.guest_agent.0' /sys/class/virtio-ports/*/name 2>/dev/null
if [ $? -eq 0 ]; then
    info 'Spice (in a VM) detected, installing guest agent'
    apk add --no-cache spice-vdagent
    rc-update add spice-vdagentd
fi

# TODO: XXX: Install VirtualBox guest tools if in the VM
da=$(cat /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/product_name /sys/class/dmi/id/board_vendor 2>/dev/null)
echo "DEBUG: $da"
if echo "$da" | grep -qi 'VirtualBox'; then
    info 'VirtualBox (in a VM) detected, installing guest tools'
    apk add --no-cache virtualbox-guest-additions virtualbox-guest-additions-x11
    rc-update add virtualbox-guest-additions boot
    rc-update add virtualbox-drm-client default
fi

# Setup devd
info 'Installing udev daemon'
setup-devd udev

info 'Creating the user'
create_user

# 13. Setup user
info 'Setting user: password stored in ~/.pw and none asked for sudo'
setup_user

# 14. SSHd
info 'Setting OpenSSHd'
setup-sshd -c openssh
# \ SSHd: Connection banner
echo '################################################################################
# Authorized Use Only. Transactions may be monitored. By continuing past this  #
# point, you expressly consent to this monitoring.                             #
################################################################################' > /etc/sshd_banner
# \ SSHd: Configuration
echo 'Port 22222
Banner /etc/sshd_banner
PasswordAuthentication no' > /etc/ssh/sshd_config.d/custom.conf
rc-service sshd reload

# 15. NTP
info 'Setting NTP'
setup-ntp busybox

info 'Setting ip[6]tables'
setup_iptables

info 'Setting Message Of The Day'
echo 'Welcome to Alpine!' > /etc/motd

info 'Autologin on TTY1'
sed -i 's#^tty1.*$#tty1::respawn:/sbin/agetty --autologin '"$_USERNAME_"' tty1 linux#' /etc/inittab

info 'Copying remaining custom configurations'
mv -f /etc/autoinstall.d/etc/profile.d/* /etc/profile.d/
mv -f /etc/autoinstall.d/etc/bash/* /etc/bash/
mkdir -p "/home/$_USERNAME_/"
mv -f /etc/autoinstall.d/.config/ "/home/$_USERNAME_/"
# gdb-gef
wget -O "/home/$_USERNAME_/.gdbinit-gef.py" -q https://gef.blah.cat/py
echo 'source ~/.gdbinit-gef.py' > "/home/$_USERNAME_/.gdbinit"
# mpd
echo 'music_directory "/home/ZIK"
bind_to_address "127.0.0.1"' >> /etc/mpd.conf

# 16. Setup disk
info 'Installing Alpine'
setup-disk -s 0 -m sys /mnt/ # No swap

# setup-disk does not copy the home directory
cp -r "/home/$_USERNAME_/" "/mnt/home/$_USERNAME_/"
chown -R "$_USERNAME_:$_USERNAME_" "/mnt/home/$_USERNAME_/"

# Keyfile embedded in the initramfs (single passphrase prompt at boot)
setup_keyfile

# Configure vim
mv -f /etc/autoinstall.d/vimrc /mnt/usr/share/vim/vimrc

# Force to use vim & bash (instead of vi & sh)
ln -sf /bin/bash /mnt/bin/sh        # Set the default shell as bash
ln -sf /usr/bin/vim /mnt/usr/bin/vi # Force using vim

# Bootloader (grub)
# setup-disk erases /etc/default/grub:
# https://github.com/alpinelinux/alpine-conf/blob/54a9488f999af2cc24535aa5aab99499f0e0b253/setup-disk.in#L358
# Configure GRUB for our layout: everything (/boot included) is in the LUKS
# volume, so GRUB must be able to unlock it (GRUB_ENABLE_CRYPTODISK).
# The root is then unlocked a second time by the initramfs, using the
# embedded keyfile (cryptkey=...), so the passphrase is asked only once.
LUKS_UUID=$(cryptsetup luksUUID "$DiskRootPath")
cat > /mnt/etc/default/grub <<EOF
GRUB_DISTRIBUTOR="Alpine"
GRUB_TIMEOUT=0
GRUB_DISABLE_SUBMENU=false
GRUB_DISABLE_RECOVERY=false
GRUB_ENABLE_CRYPTODISK=y
GRUB_DISABLE_OS_PROBER=false
GRUB_CMDLINE_LINUX_DEFAULT="modules=sd-mod,usb-storage,ext4,nvme cryptroot=UUID=$LUKS_UUID cryptdm=root cryptkey=/crypto_keyfile.bin rootfstype=ext4"
EOF
apk del syslinux # Ensure using Grub instead of syslinux
cat > /mnt/chroot.sh <<EOF
#!/bin/sh
su $_USERNAME_ -c "python -m pip install tinytuya --break-system-packages"
set -e
# Rebuild the initramfs with the keyfile embedded, then lock it down
echo 'features="ata base ide scsi usb virtio ext4 nvme cryptsetup cryptkey"' > /etc/mkinitfs/mkinitfs.conf
for k in /lib/modules/*; do mkinitfs "\${k##*/}"; done
chmod 600 /boot/initramfs-*
EOF
if [ $_UEFI_ -eq 1 ]; then
    cat >> /mnt/chroot.sh <<EOF
apk add --no-cache grub-efi efibootmgr os-prober
grub-install --efi-directory=/boot/efi --bootloader-id=alpine
EOF
else
    cat >> /mnt/chroot.sh <<EOF
apk add --no-cache grub-bios os-prober
grub-install $DiskPath
EOF
fi
# grub-install does not write grub.cfg; generate it AFTER the grub defaults
# above so GRUB_ENABLE_CRYPTODISK is taken into account.
echo 'grub-mkconfig -o /boot/grub/grub.cfg' >> /mnt/chroot.sh
chmod +x /mnt/chroot.sh
info 'Chrooting into the disk to finish the installation (initramfs + grub)...'
mount -t proc /proc/ /mnt/proc/
mount --rbind /dev/ /mnt/dev/
mount --make-rslave /mnt/dev/
mount --rbind /sys/ /mnt/sys/
chroot /mnt/ /chroot.sh && rm -f /mnt/chroot.sh
rm -rf /mnt/etc/autoinstall.d/ /mnt/etc/autoinstall.sh /mnt/etc/runlevels/default/autoinstall

printf "%%------------------------+ Installation took %02dm%02ds. +------------------------%%\n" \
    $(expr \( $(date +%s) - $START_TIME \) \/ 60) \
    $(expr \( $(date +%s) - $START_TIME \) % 60)
echo '%--------------------------+ PRESS ENTER TO REBOOT +--------------------------%'

read pause
reboot
