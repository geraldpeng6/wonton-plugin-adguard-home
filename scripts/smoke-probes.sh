# shellcheck shell=bash
# AdGuard Home 不设应用账号；身份只由网关会话验证。

web_assert() {
  grep -qi 'apple-touch-icon-180x180.png'
}

query_dns() {
  local address="$1" name="$2" transport="$3"
  if command -v dig >/dev/null 2>&1; then
    if [[ "$transport" == tcp ]]; then
      dig +time=5 +tries=1 +tcp +short "@$address" "$name" A
    else
      dig +time=5 +tries=1 +short "@$address" "$name" A
    fi
    return
  fi
  python3 - "$address" "$name" "$transport" <<'PY'
import socket
import struct
import sys

server, name, transport = sys.argv[1:]
query_id = 0x51A7
labels = b''.join(bytes([len(part)]) + part.encode() for part in name.rstrip('.').split('.')) + b'\0'
packet = struct.pack('!HHHHHH', query_id, 0x0100, 1, 0, 0, 0) + labels + struct.pack('!HH', 1, 1)
if transport == 'tcp':
    sock = socket.create_connection((server, 53), 5)
    sock.sendall(struct.pack('!H', len(packet)) + packet)
    size = sock.recv(2)
    response = sock.recv(struct.unpack('!H', size)[0])
else:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.sendto(packet, (server, 53))
    response, _ = sock.recvfrom(4096)
sock.close()
if len(response) < 12 or struct.unpack('!H', response[:2])[0] != query_id:
    raise SystemExit(1)
rcode = response[3] & 0x0f
if rcode not in (0, 3):
    raise SystemExit(1)
ancount = struct.unpack('!H', response[6:8])[0]
if rcode == 3:
    raise SystemExit(0)
pos = 12
while response[pos] != 0:
    pos += 1 + response[pos]
pos += 5
answers = []
for _ in range(ancount):
    if response[pos] & 0xc0 == 0xc0:
        pos += 2
    else:
        while response[pos]:
            pos += 1 + response[pos]
        pos += 1
    typ, cls, ttl, length = struct.unpack('!HHIH', response[pos:pos + 10])
    pos += 10
    data = response[pos:pos + length]
    pos += length
    if typ == 1 and cls == 1 and length == 4:
        answers.append(socket.inet_ntoa(data))
print('\n'.join(answers))
PY
}

probe_upstreams() {
  local jar="$1" upstream result
  for upstream in \
    'https://dns.alidns.com/dns-query' \
    'tls://dns.alidns.com' \
    '9.9.9.9' \
    'https://dns.quad9.net/dns-query' \
    'tls://dns10.quad9.net'; do
    result="$(curl -sS --noproxy '*' --fail-with-body -b "$jar" \
      -X POST -H 'Content-Type: application/json' \
      --data "$(jq -nc --arg u "$upstream" '{upstream_dns:[$u],bootstrap_dns:["223.5.5.5","2400:3200::1"],fallback_dns:[]}')" \
      "$SMOKE_WEB_URL/control/test_upstream_dns" 2>&1)" || {
        echo "上游测试请求失败：$upstream：$result"
        continue
      }
    if jq -e 'length > 0 and all(.[]; . == "OK")' >/dev/null 2>&1 <<<"$result"; then
      echo "上游可用：$upstream"
    else
      echo "上游不可用：$upstream：$result"
    fi
  done
}

identity_check() {
  SMOKE_WEB_URL="${SMOKE_WEB_URL%/}"  # 套件给的地址带尾斜杠，拼路径前剥掉，避免 // 打不进路由
  local container app_jar status anonymous page_code ports address udp tcp blocked_status blocked querylog path
  container="wonton-${SMOKE_INSTANCE}--${SMOKE_SLUG}--adguardhome"
  app_jar="$SMOKE_JAR"
  for path in / /control/status; do
    anonymous="$(curl -sS --noproxy '*' -o /dev/null -w '%{http_code}' "$SMOKE_WEB_URL$path")" || return 1
    [[ "$anonymous" == 401 ]] || { echo "网关未拒绝匿名请求 $path（HTTP $anonymous）"; return 1; }
  done
  page_code="$(curl -sS --noproxy '*' -b "$app_jar" -o /dev/null -w '%{http_code}' "$SMOKE_WEB_URL/")" || return 1
  [[ "$page_code" == 200 ]] || { echo "主人会话未直接进入管理页（HTTP $page_code）"; return 1; }
  status="$(curl -sS --noproxy '*' --fail-with-body -b "$app_jar" "$SMOKE_WEB_URL/control/status")" || {
    echo '仅用网关会话访问管理 API 失败'
    return 1
  }
  jq -e '.running == true and (.dns_addresses | length > 0)' >/dev/null <<<"$status" || {
    echo '管理 API 未报告 DNS 服务可用'
    return 1
  }
  ports="$(docker inspect --format '{{json .HostConfig.PortBindings}}' "$container")" || return 1
  jq -e 'keys | sort == ["53/tcp", "53/udp"]' >/dev/null <<<"$ports" || {
    echo '发布端口不是仅 53/tcp 和 53/udp'
    return 1
  }
  echo '网关认证通过：匿名网页/API 均 401；仅主人网关会话可直接使用管理页和 API；未发布 3000'

  address="$(docker inspect --format '{{json .NetworkSettings.Ports}}' "$container" |
    jq -r '."53/udp"[]?.HostIp // empty' |
    awk '!/^(0\.0\.0\.0|::)$/ {print; exit}')"
  [[ -n "$address" ]] || { echo "53/udp 没有发布到局域网地址"; return 1; }

  udp="$(query_dns "$address" example.com udp)" || udp=""
  tcp="$(query_dns "$address" example.com tcp)" || tcp=""
  [[ -n "$udp" ]] || { echo '宿主经 LAN 地址查询 53/udp 失败（未改防火墙）'; return 1; }
  [[ -n "$tcp" ]] || { echo '宿主经 LAN 地址查询 53/tcp 失败（未改防火墙）'; return 1; }

  blocked_status=1
  blocked=
  for _ in $(seq 1 30); do
    blocked_status=0
    blocked="$(query_dns "$address" doubleclick.net udp)" || blocked_status=$?
    if [[ "$blocked_status" == 0 ]] && grep -Eq '^(0\.0\.0\.0|::)$' <<<"$blocked"; then
      break
    fi
    sleep 2
  done
  if [[ "$blocked_status" != 0 ]]; then
    echo '宿主经 LAN 地址查询 doubleclick.net 失败（未改防火墙）'
    return 1
  fi
  if ! grep -Eq '^(0\.0\.0\.0|::)$' <<<"$blocked"; then
    echo "默认过滤清单没有拦截 doubleclick.net：$blocked"
    return 1
  fi

  probe_upstreams "$app_jar"
  sleep 1
  querylog="$(curl -sS --noproxy '*' --fail-with-body -b "$app_jar" \
    "$SMOKE_WEB_URL/control/querylog?limit=100")" || return 1
  jq -e --arg client "$address" 'any(.data[]; .client == $client)' >/dev/null <<<"$querylog" || {
    echo '查询日志未记录宿主的 LAN 来源地址'
    return 1
  }
  echo 'DNS 通过：仅从宿主经 LAN 地址测试 53/udp、53/tcp；doubleclick.net 已拦截；日志保留宿主来源地址；其他 LAN 设备未测'
}

# 数据：过滤配置和查询日志都在 ${WONTON_APP_DATA}（docker-compose.yml 的 config、work 卷）。
# data_write 走应用自己的控制 API 加一条 DNS 重写（唯一子域 → 192.0.2.10 文档地址），域名记进 SMOKE_STATE；
# data_check 在升级、重装后从重写列表读回比对。升级和重装会重建核心，会话要重建（beszel 同款做法）。
_agh_marker_file() { # 标记文件：SMOKE_STATE 在 dev.sh probes 里是目录，目录里放标记文件
  if [[ -d "${SMOKE_STATE:-}" ]]; then printf '%s/data-marker' "$SMOKE_STATE"; else printf '%s' "${SMOKE_STATE:-}"; fi
}

data_write() {
  SMOKE_WEB_URL="${SMOKE_WEB_URL%/}"  # 套件给的地址带尾斜杠，拼路径前剥掉，避免 // 打不进路由
  local marker out
  marker="wonton-$(tr -dc a-z0-9 </dev/urandom | head -c 12).smoke.invalid"
  dweb --fresh / -L >/dev/null || { echo "重建网关会话失败"; return 1; }
  out="$(curl -sS --noproxy '*' --fail-with-body -b "$SMOKE_JAR" -X POST -H 'Content-Type: application/json' \
    --data "$(jq -nc --arg d "$marker" '{domain:$d,answer:"192.0.2.10"}')" \
    "$SMOKE_WEB_URL/control/rewrite/add")" || { echo "加重写失败：$out"; return 1; }
  printf '%s' "$marker" >"$(_agh_marker_file)" || { echo "写不进标记文件 $(_agh_marker_file)"; return 1; }
  echo "已加重写 $marker → 192.0.2.10"
}

data_check() {
  SMOKE_WEB_URL="${SMOKE_WEB_URL%/}"  # 套件给的地址带尾斜杠，拼路径前剥掉，避免 // 打不进路由
  local marker out
  marker="$(cat "$(_agh_marker_file)" 2>/dev/null)" || true
  [[ -n "$marker" ]] || { echo "没有 data_write 留下的标记（SMOKE_STATE=${SMOKE_STATE:-未设置}）"; return 1; }
  dweb --fresh / -L >/dev/null || { echo "重建网关会话失败"; return 1; }
  out="$(curl -sS --noproxy '*' --fail-with-body -b "$SMOKE_JAR" "$SMOKE_WEB_URL/control/rewrite/list")" ||
    { echo "读重写列表失败：$out"; return 1; }
  jq -e --arg d "$marker" 'any(.[]; .domain == $d and .answer == "192.0.2.10")' <<<"$out" >/dev/null ||
    { echo "重写 $marker 不见了：$(head -c 200 <<<"$out")"; return 1; }
  echo "重写 $marker 还在（→ 192.0.2.10）"
}
