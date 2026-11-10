#!/bin/sh -e
#
# Copyright (c) 2026 Jacques Boscq <jacques@boscq.fr>. All rights reserved.
# This work is licensed under the terms of the MIT license.
#

HOSTNAME="$1"
if [ -z "$HOSTNAME" ]; then
	echo "usage: $0 hostname"
	exit 1
fi

cleanup() {
	rm -rf "$tmp"
}

makefile() {
	local OWNER="$1"
	local PERMS="$2"
	local FILENAME="$3"
	cat > "$FILENAME"
	chown "$OWNER" "$FILENAME"
	chmod "$PERMS" "$FILENAME"
}

rc_add() {
	mkdir -p "$tmp/etc/runlevels/$2"
	ln -sf "/etc/init.d/$1" "$tmp/etc/runlevels/$2/$1"
}

tmp="$(mktemp -d)"
trap cleanup EXIT

mkdir -p "$tmp/etc/"

# Preserve the standard live-system boot services.
touch "$tmp/etc/.default_boot_services"

scriptdir="$(dirname -- "$0")"

# Installation script
cat "$scriptdir/autoinstall.sh" | makefile root:root 0744 "$tmp/etc/autoinstall.sh"

# Launch the installation script at startup.
mkdir -p "$tmp/etc/init.d/"
makefile root:root 0744 "$tmp/etc/init.d/autoinstall" <<'EOF'
#!/sbin/openrc-run

description="Automated custom installation."

depend() {
    after *
}

start() {
    ebegin "Running custom Alpine installer"
    /etc/autoinstall.sh
    eend $?
}
EOF

rc_add autoinstall default

# Configuration files
mkdir -p "$tmp/etc/autoinstall.d/"
cp -r "$scriptdir/local_files/etc/"     "$tmp"/etc/autoinstall.d/
cp -r "$scriptdir/local_files/.config/" "$tmp"/etc/autoinstall.d/
cp    "$scriptdir/local_files/vimrc"    "$tmp"/etc/autoinstall.d/

tar -c -C "$tmp" etc | gzip -9n > $HOSTNAME.apkovl.tar.gz
