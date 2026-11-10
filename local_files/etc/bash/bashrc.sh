# https://codeberg.org/dnkl/foot/wiki#no-colors-in-ls-output
# Set LS_COLORS
#eval "$(dircolors -b)"

export LESSHISTFILE='/dev/null'

# Colored man pages, from: https://unix.stackexchange.com/questions/148/colorizing-your-terminal-and-shell-environment
function _colorman() {
  env \
    LESS_TERMCAP_mb=$'\e[1;35m' \
    LESS_TERMCAP_md=$'\e[1;34m' \
    LESS_TERMCAP_me=$'\e[0m' \
    LESS_TERMCAP_se=$'\e[0m' \
    LESS_TERMCAP_so=$'\e[7;40m' \
    LESS_TERMCAP_ue=$'\e[0m' \
    LESS_TERMCAP_us=$'\e[1;33m' \
    LESS_TERMCAP_mr=$(tput rev) \
    LESS_TERMCAP_mh=$(tput dim) \
    LESS_TERMCAP_ZN=$(tput ssubm) \
    LESS_TERMCAP_ZV=$(tput rsubm) \
    LESS_TERMCAP_ZO=$(tput ssupm) \
    LESS_TERMCAP_ZW=$(tput rsupm) \
    GROFF_NO_SGR=1 \
      "$@"
}
alias man="LANG=C _colorman man"
function perldoc() { command perldoc -n less "$@" |man -l -; }

# Easily shutdown the PC & its power outlet
# You may want to autostart your PC in the BIOS settings (Power > Secondary Power Settings > After Power Failure => Power On).
function dtc() {
    if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
        cat <<'EOF'
Usage: dtc [DURATION]...
Sleep for DURATION, then power off the system.

With no DURATION, powers off immediately.
Multiple DURATIONs are summed, same as `sleep`.

Each DURATION is a number optionally followed by a unit:
  s   seconds (default if no unit given)
  m   minutes
  h   hours
  d   days

Examples:
  dtc            power off immediately
  dtc 30m        power off in 30 minutes
  dtc 2h         power off in 2 hours
  dtc 1h 30m     power off in 1.5 hours (args are summed)
EOF
        return 0
    fi
    if [ $# -ge 1 ]; then
        local now total arg num unit shutdown_epoch
        now=$(date +%s)
        total=0

        # sum sleep-style args (10, 10s, 5m, 2h, 1d ...) into total seconds,
        # the same way `sleep` sums multiple arguments
        for arg in "$@"; do
            num="${arg%[smhd]}"
            unit="${arg: -1}"
            case "$unit" in
                m) num=$(awk "BEGIN{print $num*60}") ;;
                h) num=$(awk "BEGIN{print $num*3600}") ;;
                d) num=$(awk "BEGIN{print $num*86400}") ;;
                *) : ;;   # plain number or trailing 's' -> already seconds
            esac
            total=$(awk "BEGIN{print $total+$num}")
        done

        shutdown_epoch=$(awk "BEGIN{printf \"%d\", $now+$total}")
        echo "Shutdown scheduled for $(date -d @"$shutdown_epoch" '+%Y-%m-%d %H:%M:%S')"

        sleep "$@"
        if [ $? -ne 0 ]; then
            return $?
        fi
    fi

    #echo "Shutting down now: $(date '+%Y-%m-%d %H:%M:%S')"
    # Set a timer to shut off the power socket of the PC (after 2m) & shutdown
    if [ -f ~/.config/pc_outlet.py ]; then
        ~/.config/pc_outlet.py
    fi
    sudo poweroff
}

# Manual timer
function timer() {
    if [ $# -eq 0 ]; then
        echo 'Usage: timer TIME (format: [Xh] [Ym] [Z[s]])' > /dev/stderr
        return 1
    fi
    sleep "$@"
    if [ $? -ne 0 ]; then
        return $?
    fi
    local tmp=`echo $@ | awk '{
    for(i=1;i<=NF;i++){
        n = $i
        unit = ""
        if(match($i,/^([0-9]+)([hms]?)$/,a)){
            n = a[1]
            u = a[2]
            if(u=="h") unit = (n==1?"hour":"hours")
            else if(u=="m") unit = (n==1?"minute":"minutes")
            else if(u=="s") unit = (n==1?"second":"seconds")
            $i = n (unit? " " unit : "")
        }
    }
    # Append final "seconds" only if last field is a number without unit
    if($NF ~ /^[0-9]+$/){
        if($NF==1) final="second"
        else final="seconds"
        $0 = $0 " " final
    }
    print $0
}'`
    printf '\e[?5h'  # Turn on reverse video (flashes the terminal)
    echo "Timer ended after ${tmp}." | tee >(espeak)
    printf '\e[?5l'  # Turn on normal video
}
# Auto-sudo some commands
for i in apk dmesg modprobe mount umount updatedb; do
    alias "$i"="sudo $i"
done

# Aliases to manually power on/off the screen(s)
#alias screen_off='wlopm --off \*;read a;wlopm --on \*'
alias screen_off='wlopm --off \*'
alias screen_on='wlopm --on \*'

# Phone USB mass drive
# TODO?: use udev to automatically mount it
# It will tell if a `modprobe fuse` is required
alias mount_phone='sudo go-mtpfs /mnt/'
alias umount_phone='killall -9 go-mtpfs; umount /mnt/'

# Misc
alias radio='mpv http://millepattes.ice.infomaniak.ch/millepattes-high.mp3'
alias radio2='mpv http://hd.lagrosseradio.info:8300'

export PATH="~/.local/bin:~/.cargo/bin:$PATH"

alias apk_='apk update && apk upgrade -aU'

# Read every video (sorted by time) of the current directory with mpv
# It helps if files were downloaded in the right order but with different names
alias mpv_="ls -1tr | xargs -d '\n' mpv -fs"

# Set terminal's title
echo -ne "\033]0;$(echo $PWD | sed "s#^$HOME#~#")\007"
# Automatically updates the terminal's title with $pwd + current or last cmd
# Note: the trap should be executed the last, keep it here.
trap 'echo -ne "\033]0;$(echo $PWD | sed "s#^$HOME#~#") ${BASH_COMMAND}\007"' DEBUG
