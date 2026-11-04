# AdGuard Home：sso=none；应用自己的 admin 登录由 init 用核心生成的密码配置。
SSO=none
MCP=0

web_assert() {
  grep -qi 'apple-touch-icon-180x180.png'
}

container_env() {
  local container="$1" name="$2"
  docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$container" |
    sed -n "s/^${name}=//p"
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
  local container init_container password app_jar login status address udp tcp blocked_status blocked querylog clients
  container="wonton-${SMOKE_INSTANCE}--${SMOKE_SLUG}--adguardhome"
  init_container="wonton-${SMOKE_INSTANCE}--${SMOKE_SLUG}--init"
  password="$(container_env "$init_container" WONTON_SECRET_ADMIN_PASSWORD)"
  [[ -n "$password" ]] || { echo "init 容器里没有核心生成的 admin 密码"; return 1; }
  app_jar="$SMOKE_DIR/adguardhome.cookies"
  cp "$SMOKE_JAR" "$app_jar"
  login="$(curl -sS --noproxy '*' --fail-with-body -b "$app_jar" -c "$app_jar" \
    -X POST -H 'Content-Type: application/json' \
    -d "{\"name\":\"admin\",\"password\":\"$password\"}" \
    "$SMOKE_WEB_URL/control/login")" || {
      echo "AdGuard Home admin 登录失败：$login"
      return 1
    }
  [[ "$login" == *OK* ]] || { echo "AdGuard Home 登录没有返回 OK：$login"; return 1; }
  status="$(curl -sS --noproxy '*' --fail-with-body -b "$app_jar" "$SMOKE_WEB_URL/control/status")" || {
    echo "AdGuard Home /control/status 失败"
    return 1
  }
  jq -e '.version != null and (.dns_addresses | length > 0)' >/dev/null <<<"$status" || {
    echo "状态接口没有版本或 DNS 地址：$status"
    return 1
  }

  address="$(docker inspect --format '{{json .NetworkSettings.Ports}}' "$container" |
    jq -r '."53/udp"[]?.HostIp // empty' |
    awk '!/^(0\.0\.0\.0|::)$/ {print; exit}')"
  [[ -n "$address" ]] || { echo "53/udp 没有发布到局域网地址"; return 1; }

  udp="$(query_dns "$address" example.com udp)" || udp=""
  tcp="$(query_dns "$address" example.com tcp)" || tcp=""
  [[ -n "$udp" ]] || { echo "53/udp 查询 example.com 失败（地址 $address，未改防火墙）"; return 1; }
  [[ -n "$tcp" ]] || { echo "53/tcp 查询 example.com 失败（地址 $address，未改防火墙）"; return 1; }

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
    echo "53/udp 查询 doubleclick.net 失败（地址 $address，未改防火墙）"
    return 1
  fi
  if ! grep -Eq '^(0\.0\.0\.0|::)$' <<<"$blocked"; then
    echo "默认过滤清单没有拦截 doubleclick.net：$blocked"
    return 1
  fi

  probe_upstreams "$app_jar"
  sleep 1
  querylog="$(curl -sS --noproxy '*' --fail-with-body -b "$app_jar" \
    "$SMOKE_WEB_URL/control/querylog?limit=20" 2>/dev/null || true)"
  clients="$(jq -r '[.data[]?.client // empty] | join(",")' <<<"$querylog" 2>/dev/null || true)"
  echo "局域网 DNS 查询通过：地址=$address udp=$udp tcp=$tcp；doubleclick=$blocked；querylog 客户端=$clients"
}
