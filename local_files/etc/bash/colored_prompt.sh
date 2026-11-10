# Setup a red prompt for root and a green one for users.

_normal=$'\e[0m'
_blue=$'\e[1;34m'
if [ "$USER" = root ]; then
	_color=$'\e[1;31m'
	_symbol='#'
else
	_color=$'\e[1;32m'
	_symbol='$'
fi

# Terminal title updater: $pwd. Moved to: ~/.bashrc
#PROMPT_COMMAND='echo -ne "\033]0;$(echo "$PWD" | sed "s#^$HOME#~#")\007"'

if [ -n "$ZSH_VERSION" ]; then
	PS1="%{$_color%}%m [%{$_normal%}%~%{$_color%}]$_symbol %{$_normal%}"
else
	PS1="[\[$_color\]\A\[$_normal\]][\[$_blue\]\w\[$_normal\]]\[$_color\]$_symbol \[$_normal\]"
fi

unset _normal _blue _color _symbol
