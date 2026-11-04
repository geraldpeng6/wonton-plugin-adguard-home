#!/bin/sh
# 首次创建时用上游安装 API 生成配置；重建时只校验已有配置，保留应用设置和数据。
set -eu
umask 077

conf=/opt/adguardhome/conf/AdGuardHome.yaml
work=/opt/adguardhome/work
log=/tmp/adguardhome-init.log
base=http://127.0.0.1:3000
pid=

fail() {
  echo "init: $*" >&2
  if [ -n "${pid:-}" ]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  if [ -s "$log" ]; then
    tail -n 40 "$log" >&2 || true
  fi
  exit 1
}

stop() {
  if [ -n "${pid:-}" ]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    pid=
  fi
}
trap stop EXIT INT TERM

mkdir -p "$work"

if [ -e "$conf" ]; then
  [ -s "$conf" ] || fail "已有 AdGuardHome.yaml 是空文件，不能启用无认证配置"
  /opt/adguardhome/AdGuardHome --config "$conf" --work-dir "$work" --check-config >/dev/null 2>&1 ||
    fail "已有 AdGuardHome.yaml 校验失败"
  exit 0
fi

/opt/adguardhome/AdGuardHome \
  --config "$conf" \
  --work-dir "$work" \
  --web-addr 0.0.0.0:3000 \
  --no-check-update >"$log" 2>&1 &
pid=$!

ready=0
for _ in $(seq 1 60); do
  if wget -q -Y off -O /dev/null "$base/install.html"; then
    ready=1
    break
  fi
  kill -0 "$pid" 2>/dev/null || fail "上游首次启动失败"
  sleep 1
done
[ "$ready" = 1 ] || fail "上游安装向导未在 60 秒内就绪"

post_json() {
  wget -q -Y off -O - \
    --header 'Content-Type: application/json' \
    --post-data "$2" "$1"
}

check_body='{"web":{"ip":"0.0.0.0","port":3000,"autofix":false},"dns":{"ip":"0.0.0.0","port":53,"autofix":false},"language":""}'
check="$(post_json "$base/control/install/check_config" "$check_body")" ||
  fail "安装向导配置检查请求失败"
printf '%s' "$check" | grep -q '"dns":{"status":""' || fail "DNS 配置检查失败：$check"
printf '%s' "$check" | grep -q '"web":{"status":""' || fail "网页配置检查失败：$check"

configure='{"web":{"ip":"0.0.0.0","port":3000},"dns":{"ip":"0.0.0.0","port":53},"language":"","username":"admin","password":"'
configure=$configure$WONTON_SECRET_ADMIN_PASSWORD'"}'
post_json "$base/control/install/configure" "$configure" >/dev/null ||
  fail "安装向导写入配置失败"

for _ in $(seq 1 30); do
  [ -s "$conf" ] && break
  sleep 1
done
[ -s "$conf" ] || fail "安装 API 没有写出 AdGuardHome.yaml"
stop

# 安装 API 的默认值来自上游；家庭网络默认改用阿里公共 DNS 的 DoH 入口。
sed -i \
  -e 's#^    - https://dns10.quad9.net/dns-query$#    - https://dns.alidns.com/dns-query#' \
  -e '/^    - 149.112.112.10$/d' \
  -e 's#^    - 9.9.9.10$#    - 223.5.5.5#' \
  -e '/^    - 2620:fe::fe:10$/d' \
  -e 's#^    - 2620:fe::10$#    - 2400:3200::1#' \
  "$conf"

/opt/adguardhome/AdGuardHome --config "$conf" --work-dir "$work" --check-config >/dev/null 2>&1 ||
  fail "写入默认上游后配置校验失败"
rm -f "$log"
