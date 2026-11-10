if [ "$(tty)" = "/dev/tty1" ]; then
    export XDG_RUNTIME_DIR="$(mktemp -d)"
    #XCURSOR_THEME=simp1e-cursors XKB_DEFAULT_LAYOUT=fr dbus-launch ~/labwc/build/labwc -d 2>&1 | tee /tmp/labwc-debug.log
    XCURSOR_THEME=simp1e-cursors XKB_DEFAULT_LAYOUT=fr dbus-run-session -- labwc
fi
