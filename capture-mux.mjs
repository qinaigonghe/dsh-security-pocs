// Full mux capture: logs every /api/events.mux frame as JSONL {ts, seq, frame}.
// Usage: node capture-mux.mjs <outfile.jsonl>   (BASE env, default loopback)
import { createWriteStream } from 'node:fs'
const out = process.argv[2]
if (!out) { console.error('usage: node capture-mux.mjs <outfile.jsonl>'); process.exit(1) }
const base = process.env.BASE ?? 'http://127.0.0.1:3080'
const ws = new WebSocket(base.replace(/^http/, 'ws') + '/api/events.mux')
const f = createWriteStream(out, { flags: 'a' })
let n = 0
ws.onopen = () => console.log('[capture] mux open ->', out)
ws.onmessage = (ev) => {
  n++
  let m; try { m = JSON.parse(ev.data) } catch { return }
  f.write(JSON.stringify({ ts: Date.now(), seq: n, frame: m }) + '\n')
}
ws.onerror = (e) => console.error('[capture] error', e.message ?? e)
ws.onclose = () => { f.end(); console.log('[capture] mux closed after', n, 'frames') }
process.on('SIGINT', () => { ws.close(); setTimeout(() => process.exit(0), 200) })
