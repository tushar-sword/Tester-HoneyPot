/**
 * HoneyTrap Web Server
 * Serves the UI and streams tester.js output via Server-Sent Events.
 * 
 * Usage:
 *   npm start
 *   node server.js --port 8080
 * 
 * The tester.js and scenarios.js must be in the same directory.
 */

import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { spawn } from 'child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const args    = process.argv.slice(2);
const getArg  = (f) => { const i = args.indexOf(f); return i !== -1 ? args[i + 1] : null; };
const PORT    = parseInt(getArg('--port') || process.env.PORT || '4000');

const MIME = {
  '.html': 'text/html',
  '.js':   'application/javascript',
  '.css':  'text/css',
  '.json': 'application/json',
  '.ico':  'image/x-icon',
};

// ─── Active SSE clients (url → Set of res) ───────────────────────────────────
const sseClients = new Map();

// ─── Active child processes ──────────────────────────────────────────────────
const activeProcs = new Map(); // sessionKey → child

// ─── Parse query string ──────────────────────────────────────────────────────
function parseQuery(urlStr) {
  try {
    const u = new URL(urlStr, 'http://x');
    return Object.fromEntries(u.searchParams.entries());
  } catch (_) {
    return {};
  }
}

// ─── Send SSE event ───────────────────────────────────────────────────────────
function sendSSE(res, event, data) {
  try {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  } catch (_) {}
}

// ─── Broadcast to all SSE clients for a session ──────────────────────────────
function broadcast(sessionKey, event, data) {
  const clients = sseClients.get(sessionKey) || new Set();
  for (const res of clients) sendSSE(res, event, data);
}

// ─── HTTP Server ─────────────────────────────────────────────────────────────
const server = http.createServer((req, res) => {
  const urlObj = new URL(req.url, `http://localhost:${PORT}`);
  const pathname = urlObj.pathname;

  // ── CORS ──────────────────────────────────────────────────────────────────
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204); res.end(); return;
  }

  // ── POST /api/run — start a test ──────────────────────────────────────────
  if (req.method === 'POST' && pathname === '/api/run') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      let cfg;
      try { cfg = JSON.parse(body); } catch (_) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON' })); return;
      }

      const { url, apiKey, scenario, sessionKey } = cfg;
      if (!url || !sessionKey) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'url and sessionKey required' })); return;
      }

      // Kill any existing proc for this session
      if (activeProcs.has(sessionKey)) {
        try { activeProcs.get(sessionKey).kill('SIGTERM'); } catch (_) {}
        activeProcs.delete(sessionKey);
      }

      // Build args for tester.js
      const testerArgs = ['--url', url];
      if (apiKey)   testerArgs.push('--key', apiKey);
      if (scenario) testerArgs.push('--scenario', scenario);
      testerArgs.push('--delay', '400'); // faster for web

      const child = spawn('node', ['tester.js', ...testerArgs], {
        cwd: __dirname,
        env: { ...process.env },
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      activeProcs.set(sessionKey, child);

      broadcast(sessionKey, 'started', { pid: child.pid, args: testerArgs });

      // Stream stdout line by line
      let stdoutBuf = '';
      child.stdout.on('data', chunk => {
        stdoutBuf += chunk.toString();
        const lines = stdoutBuf.split('\n');
        stdoutBuf = lines.pop(); // keep incomplete line
        for (const line of lines) {
          broadcast(sessionKey, 'line', { text: line });
        }
      });

      child.stderr.on('data', chunk => {
        const text = chunk.toString();
        for (const line of text.split('\n')) {
          if (line.trim()) broadcast(sessionKey, 'line', { text: line, stderr: true });
        }
      });

      child.on('close', (code) => {
        if (stdoutBuf.trim()) broadcast(sessionKey, 'line', { text: stdoutBuf });
        broadcast(sessionKey, 'done', { code });
        activeProcs.delete(sessionKey);
      });

      child.on('error', (err) => {
        broadcast(sessionKey, 'error', { message: err.message });
        activeProcs.delete(sessionKey);
      });

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, pid: child.pid }));
    });
    return;
  }

  // ── POST /api/stop — kill running test ────────────────────────────────────
  if (req.method === 'POST' && pathname === '/api/stop') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      let cfg;
      try { cfg = JSON.parse(body); } catch (_) { cfg = {}; }
      const { sessionKey } = cfg;
      if (sessionKey && activeProcs.has(sessionKey)) {
        try { activeProcs.get(sessionKey).kill('SIGTERM'); } catch (_) {}
        activeProcs.delete(sessionKey);
        broadcast(sessionKey, 'stopped', {});
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
    });
    return;
  }

  // ── GET /api/stream — SSE stream ─────────────────────────────────────────
  if (pathname === '/api/stream') {
    const { sessionKey } = parseQuery(req.url);
    if (!sessionKey) {
      res.writeHead(400); res.end('sessionKey required'); return;
    }

    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',
    });
    res.write(': connected\n\n');

    if (!sseClients.has(sessionKey)) sseClients.set(sessionKey, new Set());
    sseClients.get(sessionKey).add(res);

    // Heartbeat
    const hb = setInterval(() => {
      try { res.write(': ping\n\n'); } catch (_) { clearInterval(hb); }
    }, 15000);

    req.on('close', () => {
      clearInterval(hb);
      sseClients.get(sessionKey)?.delete(res);
    });
    return;
  }

  // ── GET / — serve UI ─────────────────────────────────────────────────────
  if (pathname === '/' || pathname === '/index.html') {
    const uiPath = path.join(__dirname, 'ui.html');
    if (!fs.existsSync(uiPath)) {
      res.writeHead(404); res.end('ui.html not found'); return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(fs.readFileSync(uiPath));
    return;
  }

  // ── Static files ──────────────────────────────────────────────────────────
  const filePath = path.join(__dirname, pathname);
  if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
    const ext = path.extname(filePath);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(fs.readFileSync(filePath));
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found' }));
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n  🍯 HoneyTrap Web UI`);
  console.log(`  ─────────────────────────────────`);
  console.log(`  Local  : http://localhost:${PORT}`);
  console.log(`  Network: http://0.0.0.0:${PORT}`);
  console.log(`  ─────────────────────────────────\n`);
});