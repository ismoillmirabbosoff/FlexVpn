#!/bin/bash
USERNAME=$(head -1 "$1")
PASSWORD=$(tail -1 "$1")
USER_FILE="/etc/openvpn/users/${USERNAME}"

[ ! -f "$USER_FILE" ] && exit 1

STORED=$(cat "$USER_FILE" | tr -d '\n')

[ "$STORED" = "$PASSWORD" ] && exit 0 || exit 1
