#!/bin/bash

wallpaper_dir="$HOME/.config/wallpapers"

my_error()
{
    echo "$1" > /dev/stderr
    exit 1
}

set_background()
{
    killall -9 swaybg 2>/dev/null
    swaybg -i "$wallpaper_dir/${1}.jpg" 2>/dev/null &
    echo "$1" > "$wallpaper_dir/n"
}

download_wallpapers_and_exit()
{
    echo '[INFO] Downloading 16 wallpapers, please wait...'
    wget -q "https://www.hdwallpapers.org/wallpapers/random/" \
         -O /tmp/random-wallpapers.html
    if [ $? -ne 0 ]; then
        my_error '[ERR] Downloading the list of random wallpapers.'
    fi

    # Only use the lines after the `<div class="grid_container"...>`,
    # then retrieve the 16 first links of the random wallpapers
    links=$(awk '/<div class="grid_container"/ {found=1; next} found' \
                /tmp/random-wallpapers.html | grep -oP '(?<=href=")[^"]*' \
                | head -n 16)
    if [ $? -ne 0 -o -z "$links" ]; then
        my_error '[ERR] Fetching the list of random wallpapers.'
    fi

    i=1
    echo "$links" | while read tmp; do
        out_file="$wallpaper_dir/${i}.jpg"
        link=$(echo "${tmp}1920x1080/"|sed 's#\.org/wallpaper#\.org/download#')
        wget -q "$link" -O "$out_file"
        # Set our first downloaded wallpaper
        if [ $i -eq 1 ]; then
            set_background 1
        fi
        ((i++))
    done
    exit 0
}

# Exit if another instance is running
if [ $(pgrep -fc $(basename "$0")) -ne 1 ]; then
    my_error '[ERR] This script is already running (please wait ~5 seconds).'
fi

# First execution
if [ ! -d "$wallpaper_dir" -o ! -f "$wallpaper_dir/n" ]; then
    mkdir -p "$wallpaper_dir"
    download_wallpapers_and_exit
fi

n=$(cat "$wallpaper_dir/n")
# We have reached the last wallpaper: download more
if [ $? -ne 0 -o $n -ge 16 -o $n -le 0 ]; then
    download_wallpapers_and_exit
fi

# Otherwise, switch to the next background
((n++))
# If the file does not exist for any reason, fetch new wallpapers
if [ ! -f "$wallpaper_dir/${n}.jpg" ]; then
    echo '[WARN]: Unknown error...'
    download_wallpapers_and_exit
fi
set_background "$n"