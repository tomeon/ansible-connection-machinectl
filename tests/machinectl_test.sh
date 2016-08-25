#!/usr/bin/env bash

systemd_run_cat() {
    systemd-run -M archlinux-ansible --pty --quiet --send-sighup --unit=fafafa \
        /bin/bash -c 'read -r -p "YES?: " -t 3 line; echo "LINE => $line"'
}

machinectl_shell() {
    machinectl shell archlinux-ansible \
        /bin/bash -c 'read -r -p "YES?: " -t 3 line; echo "LINE => $line"'
}

if [[ "$1" == --pipe ]]; then
    exec 123<&0
    exec 0< <(echo "fafafafa")
    #machinectl_shell
    systemd_run_cat
    exec 0<&123
else
    #machinectl_shell
    systemd_run_cat
fi
