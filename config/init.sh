#!/bin/sh
set -eu
umask 077

conf=/opt/adguardhome/conf/AdGuardHome.yaml
if [ ! -e "$conf" ]; then
  mkdir -p "$(dirname "$conf")"
  cp /seed/AdGuardHome.yaml "$conf"
fi
