/**
 * HoneyTrap Web Server — FINAL PRODUCTION BUILD
 *
 * ROUTES:
 *   GET  /                  → serves ui.html
 *   POST /api/run           → spawns tester.js as child process
 *   POST /api/stop          → kills running child process
 *   GET  /api/stream        → SSE: streams tester.js stdout to browser
 *   POST /callback          → receives final payload POST from honeypot
 *   GET  /api/payload/:sid  → browser polls for received payload by sessionId
 *
 * HOW CALLBACK WORKS:
 *   1. server.js knows its own public URL (RENDER_EXTERNAL_URL env var on Render)
 *   2. When spawning tester.js, we inject CALLBACK_URL=https://tester-honeypot.onrender.com/callback
 *   3. tester.js reads process.env.CALLBACK_URL and uses it as callbackUrl (overrides port 3333)
 *   4. tester.js tells honeypot: "POST your final payload to CALLBACK_URL"
 *   5. Honeypot POSTs JSON to /callback on THIS server
 *   6. server.js stores payload + broadcasts via SSE to browser
 *   7. Browser renders it in the Intelligence / Payload / Score tabs
 */

import http   from 'http';
import fs     from 'fs';
import path   from 'path';
import { fileURLToPath } from 'url';
import { spawn }         from 'child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ─── Config ──────────────────────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT || '4000');

// Render sets RENDER_EXTERNAL_URL automatically — e.g. https://tester-honeypot.onrender.com
// Fall back to PUBLIC_URL env var, then localhost for local dev
const PUBLIC_URL   = (
  process.env.RENDER_EXTERNAL_URL ||
  process.env.PUBLIC_URL          ||
  `http://localhost:${PORT}`
).replace(/\/$/, '');

const CALLBACK_URL = `${PUBLIC_URL}/callback`;

const MIME = {
  '.html': 'text/html',
  '.js':   'application/javascript',
  '.css':  'text/css',
  '.json': 'application/json',
  '.ico':  'image/x-icon',
};

// ─── In-memory state ─────────────────────────────────────────────────────────
const sseClients  = new Map(); // sessionKey  → Set<ServerResponse>
const activeProcs = new Map(); // sessionKey  → ChildProcess
const payloads    = new Map(); // sessionId   → payload object  (from /callback)

// ─── Utility ─────────────────────────────────────────────────────────────────
function readBody(req) {
  return new Promise(resolve => {
    let b = '';
    req.on('data', c => { b += c.toString(); });
    req.on('end',  () => resolve(b));
  });
}

function parseQuery(urlStr) {
  try { return Object.fromEntries(new URL(urlStr, 'http://x').searchParams); }
  catch (_) { return {}; }
}

function sse(res, event, data) {
  try { res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`); } catch (_) {}
}

function broadcast(sessionKey, event, data) {
  const clients = sseClients.get(sessionKey);
  if (!clients) return;
  for (const res of clients) sse(res, event, data);
}

// Broadcast payload event to ALL open SSE connections (we don't know which
// sessionKey maps to which sessionId at broadcast time)
function broadcastPayloadAll(payload) {
  for (const [key, clients] of sseClients) {
    for (const res of clients) sse(res, 'payload', payload);
  }
}

// ─── HTTP server ─────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const urlObj   = new URL(req.url, `http://localhost:${PORT}`);
  const pathname = urlObj.pathname;

  // CORS — needed so honeypot can POST to /callback from any origin
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-api-key, Authorization');

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  // ══════════════════════════════════════════════════════════════════════════
  // POST /callback  ←  honeypot sends final intelligence payload here
  // ══════════════════════════════════════════════════════════════════════════
  if (req.method === 'POST' && pathname === '/callback') {
    const raw = await readBody(req);

    let payload;
    try { payload = JSON.parse(raw); }
    catch (_) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'invalid JSON' }));
      return;
    }

    const sid = payload?.sessionId || '__any__';
    console.log(`[callback] received  sessionId=${sid}`);

    // Store under both sessionId and wildcard
    payloads.set(sid,      payload);
    payloads.set('__any__', payload);

    // Broadcast to browser so tabs update immediately
    broadcastPayloadAll(payload);

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'received', sessionId: sid }));
    return;
  }

  // ══════════════════════════════════════════════════════════════════════════
  // GET /api/payload/:sessionId  ←  browser polls for payload
  // ══════════════════════════════════════════════════════════════════════════
  if (req.method === 'GET' && pathname.startsWith('/api/payload/')) {
    const sid = decodeURIComponent(pathname.slice('/api/payload/'.length));
    const p   = payloads.get(sid) || payloads.get('__any__') || null;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ payload: p }));
    return;
  }

  // ══════════════════════════════════════════════════════════════════════════
  // POST /api/run  ←  browser starts a test
  // ══════════════════════════════════════════════════════════════════════════
  if (req.method === 'POST' && pathname === '/api/run') {
    const raw = await readBody(req);

    let cfg;
    try { cfg = JSON.parse(raw); }
    catch (_) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON' }));
      return;
    }

    const { url, apiKey, scenario, sessionKey } = cfg;
    if (!url || !sessionKey) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'url and sessionKey required' }));
      return;
    }

    // Kill any existing proc for this session
    if (activeProcs.has(sessionKey)) {
      try { activeProcs.get(sessionKey).kill('SIGTERM'); } catch (_) {}
      activeProcs.delete(sessionKey);
    }

    // Clear stale payload for fresh run
    payloads.delete('__any__');

    // Build tester.js CLI args
    const testerArgs = ['tester.js', '--url', url, '--delay', '500', '--wait', '120'];
    if (apiKey)   testerArgs.push('--key', apiKey);
    if (scenario) testerArgs.push('--scenario', scenario);

    // Inject CALLBACK_URL so tester.js uses OUR /callback instead of port 3333
    // Also pass the honeypot credentials in env in case tester.js reads them
    const env = {
      ...process.env,
      CALLBACK_URL,                                         // ← KEY: overrides port 3333
      HONEYPOT_URL:      url,
      HONEYPOT_API_KEY:  apiKey || process.env.HONEYPOT_API_KEY || '',
    };

    const child = spawn('node', testerArgs, {
      cwd:   __dirname,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    activeProcs.set(sessionKey, child);

    // Tell the browser we started (include callbackUrl so UI can display it)
    broadcast(sessionKey, 'started', { pid: child.pid, callbackUrl: CALLBACK_URL });

    // Stream stdout line by line
    let buf = '';
    child.stdout.on('data', chunk => {
      buf += chunk.toString();
      const lines = buf.split('\n');
      buf = lines.pop(); // keep incomplete last line
      for (const line of lines) broadcast(sessionKey, 'line', { text: line });
    });

    child.stderr.on('data', chunk => {
      for (const line of chunk.toString().split('\n')) {
        if (line.trim()) broadcast(sessionKey, 'line', { text: line, stderr: true });
      }
    });

    child.on('close', code => {
      if (buf.trim()) broadcast(sessionKey, 'line', { text: buf });
      broadcast(sessionKey, 'done', { code });
      activeProcs.delete(sessionKey);
    });

    child.on('error', err => {
      broadcast(sessionKey, 'error', { message: err.message });
      activeProcs.delete(sessionKey);
    });

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, pid: child.pid, callbackUrl: CALLBACK_URL }));
    return;
  }

  // ══════════════════════════════════════════════════════════════════════════
  // POST /api/stop
  // ══════════════════════════════════════════════════════════════════════════
  if (req.method === 'POST' && pathname === '/api/stop') {
    const raw = await readBody(req);
    let cfg; try { cfg = JSON.parse(raw); } catch (_) { cfg = {}; }
    const { sessionKey } = cfg;
    if (sessionKey && activeProcs.has(sessionKey)) {
      try { activeProcs.get(sessionKey).kill('SIGTERM'); } catch (_) {}
      activeProcs.delete(sessionKey);
      broadcast(sessionKey, 'stopped', {});
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  // ══════════════════════════════════════════════════════════════════════════
  // GET /api/stream  ←  SSE connection from browser
  // ══════════════════════════════════════════════════════════════════════════
  if (pathname === '/api/stream') {
    const { sessionKey } = parseQuery(req.url);
    if (!sessionKey) { res.writeHead(400); res.end('sessionKey required'); return; }

    res.writeHead(200, {
      'Content-Type':      'text/event-stream',
      'Cache-Control':     'no-cache',
      'Connection':        'keep-alive',
      'X-Accel-Buffering': 'no',   // disable Nginx buffering on Render
    });
    res.write(': connected\n\n');

    if (!sseClients.has(sessionKey)) sseClients.set(sessionKey, new Set());
    sseClients.get(sessionKey).add(res);

    // Keepalive ping every 20s to prevent Render from dropping the connection
    const hb = setInterval(() => {
      try { res.write(': ping\n\n'); } catch (_) { clearInterval(hb); }
    }, 20000);

    req.on('close', () => {
      clearInterval(hb);
      sseClients.get(sessionKey)?.delete(res);
    });
    return;
  }

  // ══════════════════════════════════════════════════════════════════════════
  // GET /  →  ui.html
  // ══════════════════════════════════════════════════════════════════════════
  if (pathname === '/' || pathname === '/index.html') {
    const uiPath = path.join(__dirname, 'ui.html');
    if (!fs.existsSync(uiPath)) { res.writeHead(404); res.end('ui.html not found'); return; }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(fs.readFileSync(uiPath));
    return;
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Static files
  // ══════════════════════════════════════════════════════════════════════════
  const filePath = path.join(__dirname, pathname);
  if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
    const ext = path.extname(filePath);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(fs.readFileSync(filePath));
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found', path: pathname }));
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log('  ╔══════════════════════════════════════════════════════════╗');
  console.log('  ║   🍯  HONEYTRAP WEB SERVER — READY                      ║');
  console.log('  ╠══════════════════════════════════════════════════════════╣');
  console.log(`  ║   Port       : ${String(PORT).padEnd(42)}║`);
  console.log(`  ║   Public URL : ${PUBLIC_URL.padEnd(42)}║`);
  console.log(`  ║   Callback   : ${CALLBACK_URL.padEnd(42)}║`);
  console.log('  ╠══════════════════════════════════════════════════════════╣');
  console.log('  ║   SET IN YOUR HONEYPOT .env:                            ║');
  console.log(`  ║   FINAL_CALLBACK_URL=${CALLBACK_URL.padEnd(36)}║`);
  console.log('  ╚══════════════════════════════════════════════════════════╝');
  console.log('');
});