# Three Security Findings in DeepSeek Harness: Cross-Session Approval Hijacking, Forged-cwd Cross-Session Reads, and an Unauthenticated Plugin-Execution Remote

> 2026-08-15 · deepseek-harness 0.1.0-rc.5 (pre-release) @ commit `47f943859b` · all PoCs verified on the real server
>
> **Abstract.** This writeup documents three security findings in DeepSeek Harness, a plugin-based agent harness on the Cordis framework: (1) **cross-session approval / question hijacking** — a local process with no session credentials can answer another session's pending approvals and `ask_user_question` prompts; (2) **forged-cwd cross-session conversation reads** — a session that asserts the victim's workspace path reads the victim's full history through the `session_query` tool, which authorizes by `cwd` string equality; (3) an **unauthenticated Typert Remote surface** on `/api` that exposes plugin inventory, a dynamic-plugin registry, and directory listing by default, and — on deployments with the documented `tool-cordis` opt-in — arbitrary host-code execution via a `runHostHalf` approval bypass plus `invoke`. Each finding ships with a deterministic, no-API-key reproduction script in [README.md](README.md).

---

## 0. Background and threat model

DeepSeek Harness is an "everything is a plugin" agent harness:

- **Plugin tree.** The model adapter, tool registry, session log, and agent loop are Cordis plugins — composable and replaceable via configuration (`cordis.yml` / `cordis.patch.yml` overlays).
- **Event sourcing.** The session log is append-only; everything model-visible must be reconstructable from it.
- **Capability seams.** Swappable capabilities are Service Definition / Provider / Consumer triples.
- **Approval pipeline.** Dangerous tools (`danger-full-access` bash, plugin activation) request human approval through `approval/requested` frames; `ask_user_question` uses `question/requested`.
- **Dynamic plugins.** The model can write code via the `cordis_define` / `cordis_run` tools, mount it as its own plugin, and run it; host handlers run behind a facade that is explicitly not a security boundary (`cordis-host-runner/src/sandbox.ts:1-10`).
- **RPC gateway.** Typert Remote methods on `/api` are guarded only by `authority: 'trusted-host'` (loopback / configured `trustedHosts`, no Origin required).

**Threat model.** The model is a semi-trusted principal. It can be steered by prompt injection (a malicious webpage, hostile repository content, a fetched document). The attacker position used by every PoC is a **separate local process with no session ID, no tokens, and no UI** — or, on LAN-exposed deployments, a peer on the same network. The attacker's goals: approve other sessions' dangerous actions, read other sessions' secrets, or execute host code without approval.

**Methodology.** All PoCs run the real `dsh web` server. Only the model turn is scripted, using the repo's own `packages/test-support/llm-mock-server`, so the model deterministically emits the exact tool call a prompt-injected model would make. No API key is involved.

---

## 1. Finding V1 — Cross-session approval / question hijacking (CWE-862 / CWE-306)

### Mechanism

1. **`events.mux` is a global broadcast** (`packages/host/apiproxy/src/api-proxy.ts:3432-3447`):
   - `muxQueues` is a process-wide set of consumers (`:1132`);
   - any client that opens `events.mux` receives the baseline frames of **all** sessions (`for (const session of ctx.sessions.list())`) and **all** pending approval frames (`for (const pending of pendingApprovals.values())`, `:3447`);
   - `approval/requested` frames carry `sessionId / approvalId / rpcId / toolName / reason` (`requestedFrame`, `:689-700`). `question/requested` is broadcast the same way (`:1394`).
2. **`/api/respond` correlates only by wire fields** (`api-proxy.ts:3696-3720`):
   - routes by `rpcId` to the pending entry;
   - checks that the payload's `approvalId` / `sessionId` echo the entry (`approvals.schema.ts` defines only `sessionId` / `approvalId` / `outcome`);
   - there is **no binding between the responder and the session holder**, and no session-ownership token.

### Verification

`poc-v1-cross-session-approval-hijack.sh` (deterministic, no API key):

1. A victim session prompts the (scripted) model; the model emits a `bash` tool call with `sandbox_permissions: danger-full-access`, which enters the approval queue.
2. The attacker process (separate process, no session credentials) opens `events.mux` and receives the victim's `approval/requested` frame — `sessionId`, `approvalId`, `rpcId` and all.
3. The attacker `POST /api/respond` with `{outcome: "allowed-once"}` for the victim's `approvalId`; the server answers `{"accepted":true}` and the victim's `danger-full-access` command executes (probe file written outside the workspace).
4. The `VARIANT=question` run repeats the same path against `ask_user_question`; the attacker's answer is accepted and resolved for the victim session.

### Exploitation

- Session B waits for human approval of a `danger-full-access` bash escalation.
- The attacker (any local process; the bash sandbox does not isolate loopback network, so this is also reachable from inside a sandboxed model turn) subscribes to `events.mux` and receives B's `approval/requested`.
- The attacker answers with `allowed-once`; B's command runs without any human click. The identical primitive answers B's `ask_user_question` prompts.

### Why this is distinct from already-reported items

- **#250** covers the model answering the approval of **its own** session (CWE-284 self-approval).
- **Fz0x00 G-5** covers **passive eavesdropping** of `events.mux` / `events.host`.
- **This finding is cross-session answering**: any session can approve or reject another session's pending approvals and questions with no context in the victim session. The root cause is one level deeper — approval responses are not bound to session ownership, and approval data is globally broadcast. Fixing the model self-answer (e.g., requiring the answer to come from a human UI session) does not fix this finding, because the mux broadcast and the `respond` correlation never distinguish the source session.

---

## 2. Finding V2 — Forged-cwd cross-session conversation read (CWE-639)

### Mechanism

1. **`session.create` accepts any caller-asserted `cwd`** (`api-proxy.ts:2167-2183`): `const cwd = workspace?.path ?? request.payload.cwd ?? defaults.cwd`, and `ensureSession` even runs `mkdir(cwd, { recursive: true })` (`:1665`). The workspace path is caller-reported identity; the server does not validate it or require the directory to pre-exist.
2. **The `session_query` tools authorize cross-session reads by `cwd` string equality** (`packages/session-query/tool-session-query/src/workspace-access.ts:94-96`):

   ```ts
   function headerAuthorized(header, caller) {
     if (header.id === caller.id) return header.cwd === caller.header.cwd
     return caller.header.cwd !== undefined && header.cwd === caller.header.cwd
   }
   ```

   The authorization boundary is "the workspace path a session claims in its own log header" — not any authenticated identity.

**Deployment surface.** `tool-session-query` is **opt-in**: it is not mounted in the default web profile (verified with `dsh web --dump-default-config`; the package is also absent from `packages/bundle/base/package.json` dependencies). The documented enablement (the comments in `packages/bundle/web-app/cordis.patch.yml`) is for deployments that override `session-query-sqlite.config.openAt` to `first-search`/`startup` and mount the tool plugin. This finding therefore applies to **content-search deployments**; on the default deployment the model tool layer cannot reach this authorization flaw, and session-content reads reduce to the separately-reported unauthenticated `/api` surface (P16/G-2). Severity: **Medium** (opt-in).

### Verification

`poc-v2-forged-cwd-cross-session-read.sh` (deterministic, no API key; mounts the content-search overlay):

1. Victim session B is created with `cwd=<harness repo>`; its first prompt writes a unique secret: `database password is hunter2 and the production API key is sk-victim-<ts>-deadbeef (VICTIM_SECRET_<ts>)`.
2. Attacker session A is created with the **same** `cwd` — B's session ID is never used, no credentials, no tokens.
3. A's model (scripted) calls `session_search(query=VICTIM_SECRET_<ts>)`.
4. The tool result returned to A contains B's snippet in full, including the fake API key. The attacker session never touches any `/api` session-read endpoint.

### Why this is distinct from already-reported items

- **P16 / G-2** covers unauthenticated RPC direct reads of session content — the root cause is missing authentication on `/api`.
- **This finding is an authorization-design flaw**: even if `/api` gains authentication, `session.create` must still let users pick a directory, so a caller can still assert any `cwd`, and `session_query` will still trust that self-asserted path — CWE-639 stands independently.

---

## 3. Finding V3 — Unauthenticated Typert Remote surface + `runHostHalf` approval bypass (CWE-306 / CWE-862)

### Mechanism — the default-mounted Remote surface

1. **Typert Gateway intercepts `/api` Remote endpoints** (`packages/api/gateway/src/index.ts:110-118`): `connection.rpc.intercept('/api', …, { authority: 'trusted-host' })`. `isTrustedApiRequest` only requires `Host` to be loopback or in `trustedHosts` — **no Origin is required** (`packages/client/connection/src/api-request-trust.ts:96-118`).
2. **The default web profile mounts** the Remote surface: `plugin-inventory` (`packages/bundle/web-app/cordis.patch.yml:94-95`), the API gateway (`:99-100`), `cordis-host-runner` (`:102-103`), and `api-remotes` (`:165-166`); the Typert gateway itself is `@deepseek-ai/dsh-api-gateway` from the base bundle (`packages/bundle/base/cordis.patch.yml:36-37`). With no configuration change:
   - `pluginInventory/list` → the Loader's full plugin inventory (module names, states);
   - `dynamicCordisRunner/inventory` → the dynamic-plugin registry, including `pluginId` / `activeRun.pluginRunId`;
   - `host.listDirectory` → directory listing once a browse capability is composed (the PoC demonstrates the headless browse overlay).
3. **LAN extension.** The CLI rejects `--host 0.0.0.0`, but the `webserver.host` schema accepts it (`packages/host/webserver/src/index.ts`). When bound to `0.0.0.0`, `resolveLanTrust` (`packages/bundle/web-app/src/index.ts:73-91`) automatically adds the host's LAN IPv4 addresses to `trustedHosts` — a LAN peer passes the Host fence with no Origin.

### Mechanism — the `runHostHalf` approval bypass

1. `runHostHalf` (`cordis-host-runner/src/index.ts:324-377`): the `requestId: null` branch is designed as the "human clicked run in the UI" gesture. It performs **no approval and no holder check** — the only ownership check is `plugin?.sessionId === agent.id` in `owned()` (where `Agent.id` is the `SessionId`; `packages/core/agent/src/runtime-types.ts:66`), and `agent` is resolved from a **caller-supplied `sessionId` string** (`packages/api/remotes/src/agent-lookup.ts`). The wire key is `agentId` (Typert-generated `packages/extensions/cordis-host-runner/lib/typert.host.js`).
2. `invoke(pluginId, pluginRunId, method, args)` (`index.ts:740-762`): no agent / ownership validation — if a plugin is running and the run ID matches, it calls `run.handlers.get(method)(args)` directly. Any running plugin's host handler is executable.
3. `cordis/request-run` events are forwarded to every `events.mux` subscriber (`packages/api/remotes/src/remote-events.ts` allowlist; `api-proxy.ts:3616-3628`), leaking pending activation `requestId / agentId / pluginId / packageId / mode`.
4. The host half is not a sandbox (`cordis-host-runner/src/sandbox.ts:1-10`): `ctx.bash` / `ctx.fs` / `ctx.web` and `harness.defineTool` / `registerTool` reach the real runtime; `harness.handle(method, fn)` registers the exact handler `invoke` executes.

### Verification

`poc-v3-typert-runhosthalf-bypass.sh` (deterministic, no API key; mounts the documented `tool-cordis` opt-in):

1. The victim session's model (scripted) calls `cordis_define` and defines plugin `pwn-1` with a host handler `harness.handle('pwn', …)`. The plugin is **defined but never run and never approved**.
2. The attacker (a separate `curl`, no session) calls `dynamicCordisRunner/runHostHalf` with `{"agentId":"<plugin.sessionId>","pluginId":"pwn-1","packageId":"pkg-1","mode":"run","requestId":null,"approveFutureVersions":true}` → `{"ok":true,"pluginRunId":"run-1","startedHere":true}` — the plugin is activated **without any human approval**.
3. The attacker calls `dynamicCordisRunner/invoke` with `{"pluginId":"pwn-1","pluginRunId":"run-1","method":"pwn","args":{"hello":"from-attacker"}}` → `{"ok":true,"value":{"pwned":true,"marker":"DSH-RH-<ts>","arg":{…}}}` — the host handler executed with host-runtime permissions.

`poc-v3b-typert-unauthenticated-surface.sh` (no API key, no LLM, default profile): `pluginInventory/list` returns the Loader inventory (133 entries on the test instance), `dynamicCordisRunner/inventory` returns `ok:true`, and `host.listDirectory` returns a 48-entry directory listing under the browse overlay — all unauthenticated.

### Why this is distinct from already-reported items

- **P16 / G-2** covers unauthenticated RPC direct reads of session/host data. This finding is an unauthenticated **Remote service surface** (mounted by default) whose `invoke` method is an execute-arbitrary-running-plugin-code primitive and whose `runHostHalf` is a plugin-activation **approval bypass** primitive.
- **#250 / Fz0x00 G-5** cover passive mux eavesdropping and self-answering approvals. This finding combines the mux broadcast (`cordis/request-run`) with Remote methods into an **active execution chain**.
- **G-4** (LAN/`trustedHosts` not pinned) was originally reported as a P2 documentation-level item; this finding provides a reproducible default surface plus an opt-in RCE chain, upgrading it to P1.

---

## 4. Remediation summary

- **V1** — scope `events.mux` per session so consumers only receive their own session's approvals/questions/events (or hide `approvalId`/`rpcId` from non-holders); bind `respond` to session ownership with a one-time token issued only to the human UI; minimal fix: require the responder to be same-session and a UI source.
- **V2** — `session_query` authorization must not key off the `header.cwd` string; use the existing workspace registry / session ownership, or add user approval for cross-session reads; constrain `session.create` `cwd` to registered workspaces (which also removes the arbitrary `mkdir -p` side effect).
- **V3 / V3b** — bind Remote methods (`inventory` / `invoke` / `resolveRequestRun` / `runHostHalf`) to session ownership and validate `plugin.sessionId === agent.session.id` for the real holder; the `requestId: null` branch of `runHostHalf` must require the human-UI one-time token; stop broadcasting `cordis/request-run` on the global mux (or deliver `requestId` only to the holder session); restrict `host.listDirectory` to registered workspaces; do not auto-add all LAN IPs to `trustedHosts`.

## 5. Severity notes

Using CVSS 3.1 with a local attack surface (AV:L/AC:L/PR:N/UI:N):

- **V1** — High, ≈ 7.8–8.8.
- **V2** — Medium on content-search (opt-in) deployments, ≈ 4.3–5.9.
- **V3 / V3b** — default surface ≈ 5.3–6.5 (information disclosure + approval primitives); with the documented `tool-cordis` opt-in ≈ 7.5–8.8 (local arbitrary code execution); on `0.0.0.0` LAN bindings, raise by 1–2 steps for AV:A.

## 6. Reproduction notes

- Anchor: deepseek-harness `0.1.0-rc.5` @ `47f943859b`; PoCs require a source checkout with `pnpm install` and a sibling (or `REPO`-pointed) layout — see [README.md](README.md).
- All four scripts are deterministic and need no API key; they start and stop their own `dsh web` and mock-LLM processes, and print the captured evidence frames.
- Runtime evidence captures (mux JSONL, RPC responses) are gitignored; `capture-mux.mjs` (committed) is the only helper the scripts need.
