#!/bin/sh
# 网页仅经网关登录访问；已有配置只移除应用账号，保留 DNS 设置和数据。
set -eu
umask 077

conf=/opt/adguardhome/conf/AdGuardHome.yaml
work=/opt/adguardhome/work
pending=$conf.new
trap 'rm -f "$pending"' EXIT

mkdir -p "$(dirname "$conf")" "$work"
if [ -e "$conf" ]; then
  [ -s "$conf" ] || { echo 'init: 已有 AdGuardHome.yaml 是空文件' >&2; exit 1; }
  # 上游写出的 users 是顶层块；整块删除，不能只删密码而留下账号。
  awk '
    /^[[:alnum:]_]+:/ { users = ($0 ~ /^users:/) }
    !users { print }
  ' "$conf" >"$pending"
else
  cp /seed/AdGuardHome.yaml "$pending"
fi

/opt/adguardhome/AdGuardHome --config "$pending" --work-dir "$work" --check-config || {
  echo 'init: AdGuardHome.yaml 校验失败，未替换配置' >&2
  exit 1
}
mv "$pending" "$conf"
