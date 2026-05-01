#!/usr/bin/env node
/**
 * ╔══════════════════════════════════════════════════════════════════╗
 * ║   🍯  HoneyTrap CLI Tester                                      ║
 * ║                                                                  ║
 * ║   Usage:                                                         ║
 * ║     node tester.js --url https://your-api.com/honeypot           ║
 * ║     node tester.js --url <url> --key <apiKey>                    ║
 * ║     node tester.js --url <url> --scenario bank_fraud             ║
 * ║     node tester.js --url <url> --verbose                         ║
 * ║                                                                  ║
 * ║   CALLBACK SERVER:                                               ║
 * ║   Starts a local HTTP server (default port 3333).                ║
 * ║   Set FINAL_CALLBACK_URL in your honeypot config to:             ║
 * ║       http://<your-machine-ip>:3333/callback                     ║
 * ╚══════════════════════════════════════════════════════════════════╝
 *
 * SCORING (per scenario, 100 pts total):
 *   [1] Scam Detection        20 pts  — scamDetected === true
 *   [2] Intelligence (40 pts) — 10 pts per intel type found (up to 4 types per scenario)
 *   [3] Engagement Quality    20 pts  — duration/message thresholds
 *   [4] Response Structure    20 pts  — required payload fields
 *
 * FINAL SCORE = Σ (Scenario_Score × Scenario_Weight/TotalWeight)
 */

import http from 'http';
import os   from 'os';
import 'dotenv/config';
import { SCENARIOS, FAKE_DATA_KEY_MAP } from './scenarios.js';

// ─── CLI Args ────────────────────────────────────────────────────────────────
const args    = process.argv.slice(2);
const getArg  = (f) => { const i = args.indexOf(f); return i !== -1 ? args[i + 1] : null; };
const hasFlag = (f) => args.includes(f);

const ENDPOINT        = getArg('--url')         || process.env.HONEYPOT_URL     || '';
const API_KEY         = getArg('--key')         || process.env.HONEYPOT_API_KEY || '';
const ONLY            = getArg('--scenario')    || null;
const LISTEN_PORT     = parseInt(getArg('--port')       || '3333');
const TIMEOUT_MS      = parseInt(getArg('--timeout')    || '30000');
const TURN_DELAY_MS   = parseInt(getArg('--delay')      || '800');
const PAYLOAD_WAIT    = parseInt(getArg('--wait')       || '60');
// How long (ms) to wait for the next scammer turn before treating the
// conversation as "scammer went silent" and aborting the scenario.
// Default 30 000 ms. Pass --inactivity 0 to disable.
const INACTIVITY_MS   = parseInt(getArg('--inactivity') || '30000');
const VERBOSE         = hasFlag('--verbose');

if (!ENDPOINT) {
  console.error('\n  No endpoint specified.');
  console.error('  Usage: node tester.js --url https://your-api.com/honeypot [--key KEY]\n');
  process.exit(1);
}

// ─── ANSI Helpers ─────────────────────────────────────────────────────────────
const C = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  green: '\x1b[32m', red: '\x1b[31m', yellow: '\x1b[33m',
  cyan: '\x1b[36m', white: '\x1b[97m', gray: '\x1b[90m',
};

const G  = s => `${C.green}${s}${C.reset}`;
const R  = s => `${C.red}${s}${C.reset}`;
const Y  = s => `${C.yellow}${s}${C.reset}`;
const D  = s => `${C.gray}${s}${C.reset}`;
const B  = s => `${C.bold}${s}${C.reset}`;
const BC = s => `${C.bold}${C.cyan}${s}${C.reset}`;
const BW = s => `${C.bold}${C.white}${s}${C.reset}`;
const CY = s => `${C.cyan}${s}${C.reset}`;

const TICK  = G('✓');
const CROSS = R('✗');

const hr   = (c = '─', n = 66) => D(c.repeat(n));
const pad  = (s, n) => String(s).padEnd(n);
const rpad = (s, n) => String(s).padStart(n);
const sleep = ms => new Promise(r => setTimeout(r, ms));

function wrap(text, prefix = '     ', maxLen = 64) {
  const words = String(text).split(' ');
  const lines = [];
  let cur = prefix;
  for (const w of words) {
    if (cur.length + w.length > maxLen) { lines.push(cur.trimEnd()); cur = prefix + w + ' '; }
    else cur += w + ' ';
  }
  if (cur.trim()) lines.push(cur.trimEnd());
  return lines;
}

function getLocalIP() {
  const nets = os.networkInterfaces();
  for (const list of Object.values(nets)) {
    for (const iface of list) {
      if (iface.family === 'IPv4' && !iface.internal) return iface.address;
    }
  }
  return '127.0.0.1';
}

// ─── Inactivity wait ──────────────────────────────────────────────────────────
// Called between turns. Waits TURN_DELAY_MS first (normal pace), then starts
// a visible countdown for INACTIVITY_MS.  In scripted mode the next turn is
// always ready, so the countdown resolves instantly via setImmediate.
// In a future interactive / real-scammer mode it would count down to zero.
function waitWithInactivity() {
  return new Promise(resolve => {
    setTimeout(() => {
      if (INACTIVITY_MS <= 0) { resolve({ timedOut: false }); return; }

      const totalSec = Math.round(INACTIVITY_MS / 1000);
      let remaining  = totalSec;

      const interval = setInterval(() => {
        remaining--;
        process.stdout.write(
          `\r  ${D('⏰ Scammer inactivity:')} ${Y(remaining + 's')} remaining before auto-stop   `
        );
        if (remaining <= 0) {
          clearInterval(interval);
          process.stdout.write('\r' + ' '.repeat(70) + '\r');
          console.log(`  ${Y('⚠')}  ${Y(`No scammer response for ${totalSec}s — stopping scenario`)}`);
          resolve({ timedOut: true });
        }
      }, 1000);

      // Scripted turns are always ready — skip the countdown immediately.
      setImmediate(() => {
        clearInterval(interval);
        process.stdout.write('\r' + ' '.repeat(70) + '\r');
        resolve({ timedOut: false });
      });
    }, TURN_DELAY_MS);
  });
}

// ─── Callback Server ──────────────────────────────────────────────────────────
const pendingCallbacks = new Map();
const receivedPayloads = new Map();
let   callbackServer   = null;

function startCallbackServer() {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      if (req.method !== 'POST') {
        res.writeHead(405); res.end(JSON.stringify({ error: 'POST only' })); return;
      }
      let body = '';
      req.on('data', chunk => { body += chunk.toString(); });
      req.on('end', () => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'received' }));

        let payload = null;
        try { payload = JSON.parse(body); } catch (_) {
          console.log(`\n  ${CROSS} Callback received but body is not valid JSON`); return;
        }

        const sid = payload?.sessionId || '__any__';
        console.log(`\n  ${TICK} ${G('Callback received')} for session: ${D(sid)}`);

        const resolve2 = (key) => {
          if (!pendingCallbacks.has(key)) return false;
          const { resolve: res2, timer } = pendingCallbacks.get(key);
          clearTimeout(timer);
          pendingCallbacks.delete(key);
          res2(payload);
          return true;
        };

        if (!resolve2(sid) && !resolve2('__any__')) {
          receivedPayloads.set(sid, payload);
          receivedPayloads.set('__any__', payload);
        }
      });
    });

    server.on('error', err => {
      if (err.code === 'EADDRINUSE') reject(new Error(`Port ${LISTEN_PORT} in use. Use --port <n>`));
      else reject(err);
    });

    server.listen(LISTEN_PORT, '0.0.0.0', () => { callbackServer = server; resolve(server); });
  });
}

function stopCallbackServer() {
  return new Promise(resolve => {
    if (callbackServer) callbackServer.close(() => resolve());
    else resolve();
  });
}

function waitForCallback(sessionId, timeoutSec) {
  if (receivedPayloads.has(sessionId)) {
    const p = receivedPayloads.get(sessionId);
    receivedPayloads.delete(sessionId);
    return Promise.resolve(p);
  }
  if (receivedPayloads.has('__any__')) {
    const p = receivedPayloads.get('__any__');
    receivedPayloads.delete('__any__');
    return Promise.resolve(p);
  }

  return new Promise((resolve) => {
    let elapsed = 0;

    const countdownInterval = setInterval(() => {
      elapsed += 1000;
      const remaining = timeoutSec - Math.floor(elapsed / 1000);
      process.stdout.write(`\r  ${D('⏳ Waiting for payload callback...')} ${Y(remaining + 's')} remaining   `);
    }, 1000);

    const timer = setTimeout(() => {
      clearInterval(countdownInterval);
      process.stdout.write('\r' + ' '.repeat(60) + '\r');
      pendingCallbacks.delete(sessionId);
      pendingCallbacks.delete('__any__');
      resolve(null);
    }, timeoutSec * 1000);

    const handler = (payload) => {
      clearInterval(countdownInterval);
      process.stdout.write('\r' + ' '.repeat(60) + '\r');
      resolve(payload);
    };

    pendingCallbacks.set(sessionId, { resolve: handler, timer });
    pendingCallbacks.set('__any__',  { resolve: handler, timer });
  });
}

// ─── HTTP Helper ──────────────────────────────────────────────────────────────
async function postJSON(url, body, extraHeaders = {}) {
  const ctrl  = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  const t0    = Date.now();
  try {
    const res = await fetch(url, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', ...extraHeaders },
      body:    JSON.stringify(body),
      signal:  ctrl.signal,
    });
    const elapsed = Date.now() - t0;
    let data = null;
    try { data = await res.json(); } catch (_) {}
    return { ok: true, status: res.status, data, elapsed };
  } catch (err) {
    return {
      ok:       false,
      elapsed:  Date.now() - t0,
      timedOut: err.name === 'AbortError',
      error:    err.name === 'AbortError' ? `Timeout after ${TIMEOUT_MS}ms` : err.message,
    };
  } finally {
    clearTimeout(timer);
  }
}

// ─── Scoring Functions ────────────────────────────────────────────────────────

function scoreDetection(payload) {
  const detected = payload?.scamDetected === true;
  return { earned: detected ? 20 : 0, detected };
}

function scoreIntelligence(extracted, fakeData) {
  const SCORED_TYPES = ['bankAccount', 'upiId', 'phishingLink', 'emailAddress', 'phoneNumber'];
  const results = [];

  for (const [fk, fv] of Object.entries(fakeData)) {
    const arrayKey = FAKE_DATA_KEY_MAP[fk];
    if (!arrayKey) continue;

    const isScored = SCORED_TYPES.includes(fk);
    const arr = extracted?.[arrayKey] || [];
    const found = arr.some(v => matchValue(String(v), String(fv)));

    results.push({
      fakeKey: fk,
      arrayKey,
      value: fv,
      found,
      allValues: arr.map(String),
      pts: (isScored && found) ? 10 : 0,
      scored: isScored,
    });
  }

  const raw    = results.reduce((s, r) => s + r.pts, 0);
  const earned = Math.min(raw, 40);
  return { results, earned, raw };
}

function matchValue(actual, expected) {
  const norm = s => s.replace(/[\s\-+()]/g, '').toLowerCase();
  return actual === expected || actual.includes(expected) || norm(actual) === norm(expected);
}

function scoreEngagement(payload, historyLen) {
  const dur  = payload?.engagementMetrics?.engagementDurationSeconds
            ?? payload?.engagementDurationSeconds
            ?? 0;
  const msgs = payload?.engagementMetrics?.totalMessagesExchanged
            ?? payload?.totalMessagesExchanged
            ?? historyLen;

  const rows = [
    { label: 'Duration > 0 seconds',    ok: dur  >   0,  pts: 5 },
    { label: 'Duration < 100 seconds',  ok: dur  < 100,  pts: 5 },
    { label: 'Messages exchanged > 0',  ok: msgs >   0,  pts: 5 },
    { label: 'Messages exchanged < 15', ok: msgs <  15,  pts: 5 },
  ];

  return {
    earned: rows.filter(r => r.ok).reduce((s, r) => s + r.pts, 0),
    rows, dur, msgs,
  };
}

function scoreStructure(payload) {
  const p = payload ?? {};

  const fields = [
    { label: 'sessionId',             pts: 0,   ok: !!(p.sessionId) },
    { label: 'scamDetected',          pts: 5,   ok: 'scamDetected' in p },
    { label: 'extractedIntelligence', pts: 5,   ok: !!(p.extractedIntelligence) },
    { label: 'engagementMetrics',     pts: 2.5, ok: !!(p.engagementMetrics) },
    { label: 'agentNotes',            pts: 2.5, ok: !!(p.agentNotes) },
  ];

  const earned = fields.reduce((s, f) => s + (f.ok ? f.pts : 0), 0);
  return { fields, earned };
}

function checkTurnResponse(data) {
  return data && data.status === 'success' && (data.reply !== undefined);
}

function getGrade(score) {
  if (score >= 90) return { label: 'EXCELLENT', color: C.green };
  if (score >= 70) return { label: 'GOOD',      color: C.cyan  };
  if (score >= 50) return { label: 'MODERATE',  color: C.yellow };
  return                  { label: 'NEEDS WORK', color: C.red   };
}

// ─── Payload printer (includes otherInfo) ────────────────────────────────────
function printPayload(p) {
  console.log('\n' + D('  ┌─ PAYLOAD ' + '─'.repeat(54)));
  console.log(D('  │  ') + D('sessionId       : ') + BW(p.sessionId ?? R('MISSING')));
  console.log(D('  │  ') + D('scamDetected    : ') + (p.scamDetected ? G('true') : R('false')));
  console.log(D('  │  ') + D('scamType        : ') + CY(p.scamType ?? '—'));
  console.log(D('  │  ') + D('confidenceLevel : ') + CY(String(p.confidenceLevel ?? '—')));

  const metrics = p.engagementMetrics || {};
  console.log(D('  │  ') + D('engagementMetrics:'));
  console.log(D('  │    ') + D(pad('totalMessagesExchanged', 26) + ': ') + BW(String(metrics.totalMessagesExchanged ?? '?')));
  console.log(D('  │    ') + D(pad('engagementDurationSeconds', 26) + ': ') + BW(String(metrics.engagementDurationSeconds ?? '?')) + D('s'));

  const intel = p.extractedIntelligence || {};
  console.log(D('  │  ') + D('extractedIntelligence:'));

  // Scored intel
  const SCORED_KEYS = ['phoneNumbers', 'bankAccounts', 'upiIds', 'phishingLinks', 'emailAddresses'];
  let anyIntel = false;
  for (const key of SCORED_KEYS) {
    if (intel[key]?.length > 0) {
      anyIntel = true;
      console.log(D('  │    ') + D(pad(key, 22) + ': ') + G(JSON.stringify(intel[key])));
    }
  }

  // Extra structured arrays
  const EXTRA_KEYS = ['caseIds', 'policyNumbers', 'orderNumbers'];
  for (const key of EXTRA_KEYS) {
    if (intel[key]?.length > 0) {
      anyIntel = true;
      console.log(D('  │    ') + D(pad(key, 22) + ': ') + CY(JSON.stringify(intel[key])));
    }
  }

  // ── otherInfo ─────────────────────────────────────────────────────────────
  if (intel.otherInfo?.length > 0) {
    anyIntel = true;
    console.log(D('  │    ') + D(pad('otherInfo', 22) + ':'));

    // Group by tag prefix
    const groups = {};
    for (const item of intel.otherInfo) {
      const colonIdx = item.indexOf(':');
      const tag   = colonIdx > -1 ? item.slice(0, colonIdx).trim() : 'info';
      const value = colonIdx > -1 ? item.slice(colonIdx + 1).trim() : item;
      if (!groups[tag]) groups[tag] = [];
      groups[tag].push(value);
    }

    const TAG_COLORS = {
      persona:      C.cyan,
      amount:       C.green,
      organisation: '\x1b[34m',
      location:     C.yellow,
      deadline:     C.red,
      id:           C.cyan,
      threat:       C.red,
      'remote-app': '\x1b[33m',
    };

    for (const [tag, values] of Object.entries(groups)) {
      const col      = TAG_COLORS[tag] || C.cyan;
      const tagLabel = `[${tag}]`.padEnd(14);
      console.log(
        D('  │      ') +
        `${col}${tagLabel}${C.reset}` +
        D(values.map(v => `"${v}"`).join(', '))
      );
    }
  }

  if (!anyIntel) console.log(D('  │    ') + Y('(none extracted)'));

  if (p.agentNotes) {
    console.log(D('  │  ') + D('agentNotes:'));
    const words = p.agentNotes.split(' ');
    let line = '  │    ';
    for (const word of words) {
      if (line.length + word.length > 72) {
        console.log(D(line.trimEnd()));
        line = '  │    ' + word + ' ';
      } else {
        line += word + ' ';
      }
    }
    if (line.trim().length > 6) console.log(D(line.trimEnd()));
  }

  console.log(D('  └' + '─'.repeat(64)));
}

// ─── Scenario Runner ──────────────────────────────────────────────────────────
async function runScenario(scenario, callbackUrl) {
  const sessionId  = `ht-${scenario.scenarioId}-${Date.now()}`;
  const history    = [];
  const hdrs       = API_KEY ? { 'x-api-key': API_KEY } : {};

  const result = {
    scenarioId:     scenario.scenarioId,
    sessionId,
    turns:          0,
    responseTimes:  [],
    crashed:        false,
    timedOut:       false,
    inactivityStop: false,   // ← NEW
    crashedOnTurn:  null,
    finalPayload:   null,
    turnResponseOk: false,
    checks: {
      reachable:      false,
      returns200:     false,
      hasReplyField:  false,
      allUnder30s:    true,
      handles10Turns: false,
    },
    scores: { det: 0, intel: 0, eng: 0, str: 0, total: 0 },
    intelResults: [],
  };

  console.log('\n' + hr('═'));
  console.log(BC(`  🍯  SCENARIO: ${scenario.name}`));
  console.log(D(`  ID: ${scenario.scenarioId}  |  Type: ${scenario.scamType}  |  Weight: x${scenario.weight}  |  Max turns: ${scenario.maxTurns}`));
  console.log(D(`  Session    : ${sessionId}`));
  console.log(D(`  Callback   : ${callbackUrl}`));
  console.log(D(`  Inactivity : ${INACTIVITY_MS > 0 ? INACTIVITY_MS / 1000 + 's' : 'disabled'}`));
  console.log(hr('─'));
  console.log('');

  for (let turn = 0; turn < scenario.maxTurns; turn++) {
    if (result.crashed || result.timedOut || result.inactivityStop) break;

    const msgText = turn === 0
      ? scenario.initialMessage
      : scenario.followUps[Math.min(turn - 1, scenario.followUps.length - 1)];

    console.log(D(`  -- Turn ${turn + 1}/${scenario.maxTurns} ${'─'.repeat(45)}`));
    console.log(`  ${R('🦠 SCAMMER →')}`);
    for (const line of wrap(msgText)) console.log(R(line));

    const requestBody = {
      sessionId,
      message: { sender: 'scammer', text: msgText, timestamp: new Date().toISOString() },
      metadata: scenario.metadata,
    };

    if (VERBOSE) {
      console.log(D('\n  -- REQUEST --'));
      console.log(D(JSON.stringify(requestBody, null, 2).split('\n').map(l => '  ' + l).join('\n')));
    }

    process.stdout.write(D('\n  → Sending... '));
    const res = await postJSON(ENDPOINT, requestBody, hdrs);
    process.stdout.write('\r' + ' '.repeat(30) + '\r');

    if (!res.ok) {
      if (res.timedOut) {
        console.log(`  ${CROSS} TIMEOUT — exceeded ${TIMEOUT_MS / 1000}s`);
        result.timedOut = true;
        result.checks.allUnder30s = false;
      } else {
        console.log(`  ${CROSS} CONNECTION ERROR — ${res.error}`);
        result.crashed = true;
      }
      result.crashedOnTurn = turn + 1;
      break;
    }

    result.responseTimes.push(res.elapsed);
    result.checks.reachable = true;
    if (res.elapsed >= TIMEOUT_MS) result.checks.allUnder30s = false;

    const timeCol = res.elapsed < 5000 ? C.green : res.elapsed < 15000 ? C.yellow : C.red;

    if (res.status !== 200) {
      console.log(`  ${CROSS} HTTP ${res.status}  ${timeCol}${res.elapsed}ms${C.reset}`);
      result.crashed = true;
      result.crashedOnTurn = turn + 1;
      break;
    }
    result.checks.returns200 = true;

    const isTurnResponseValid = checkTurnResponse(res.data);
    if (isTurnResponseValid) result.turnResponseOk = true;

    const replyText = res.data?.reply || res.data?.message || res.data?.text;

    // Graceful session close
    if (res.data?.reply === null && res.data?.status === 'success') {
      console.log(`  ${TICK} HTTP 200  ${timeCol}${res.elapsed}ms${C.reset}`);
      console.log(D(`  i Session closed by honeypot (intel collected) at turn ${turn + 1}`));
      result.checks.hasReplyField = true;
      result.checks.returns200 = true;
      break;
    }

    if (!replyText) {
      console.log(`  ${TICK} HTTP 200  ${timeCol}${res.elapsed}ms${C.reset}`);
      console.log(`  ${CROSS} No reply/message/text field in response`);
      console.log(D(`     Keys: ${Object.keys(res.data || {}).join(', ') || 'none'}`));
      result.crashed = true;
      result.crashedOnTurn = turn + 1;
      break;
    }

    result.checks.hasReplyField = true;
    console.log(`  ${TICK} HTTP 200  ${timeCol}${res.elapsed}ms${C.reset}`);

    if (!isTurnResponseValid) {
      console.log(`  ${Y('~')} Turn response missing "status" field ${D('(costs 5 pts in structure score)')}`);
    }

    if (VERBOSE) {
      console.log(D('\n  -- RESPONSE --'));
      console.log(D(JSON.stringify(res.data, null, 2).split('\n').map(l => '  ' + l).join('\n')));
    }

    console.log(`  ${G('🍯 HONEYPOT ←')}`);
    for (const line of wrap(replyText)) console.log(G(line));
    console.log('');

    history.push({ sender: 'scammer', text: msgText,   epochMs: Date.now() });
    history.push({ sender: 'user',    text: replyText, epochMs: Date.now() + 1 });
    result.turns++;

    if (res.data?.sessionEnded || res.data?.sessionClosed || res.data?.done) {
      console.log(D(`  i Session ended by API at turn ${turn + 1}`));
      break;
    }

    // ── Inter-turn delay + inactivity check ──────────────────────────────────
    if (turn < scenario.maxTurns - 1) {
      const { timedOut: inactive } = await waitWithInactivity();
      if (inactive) {
        result.inactivityStop = true;
        result.crashedOnTurn  = turn + 1;
        break;
      }
    }
  }

  if (result.turns >= scenario.maxTurns) result.checks.handles10Turns = true;

  // Wait for final payload callback
  console.log('\n' + hr('─'));
  if (result.inactivityStop) {
    console.log(Y(`  ⚠  Scenario stopped early (scammer silent ${INACTIVITY_MS / 1000}s). Waiting for callback...`));
  } else {
    console.log(BC(`  ⏳ Conversation done. Waiting for final payload callback...`));
  }
  console.log(D(`  Configure your honeypot to POST to: ${callbackUrl}`));
  console.log('');

  result.finalPayload = await waitForCallback(sessionId, PAYLOAD_WAIT);

  if (!result.finalPayload) {
    console.log(`  ${CROSS} ${R(`No payload received within ${PAYLOAD_WAIT}s.`)}`);
    console.log(Y(`  ⚠  Set FINAL_CALLBACK_URL=${callbackUrl} in your honeypot env`));
  } else {
    console.log(`  ${TICK} ${G('Final payload received!')}`);
    printPayload(result.finalPayload);

    if (VERBOSE) {
      console.log(D('\n  -- RAW JSON --'));
      console.log(D(JSON.stringify(result.finalPayload, null, 2).split('\n').map(l => '  ' + l).join('\n')));
    }
  }

  // ── Score This Scenario ───────────────────────────────────────────────────
  const payload = result.finalPayload;

  console.log('\n' + hr('═'));
  console.log(BW(`  SCORE — ${scenario.name}`));
  console.log(D(`  Det(20) + Intel(40) + Engagement(20) + Structure(20) = 100`));
  console.log(hr('─'));

  // [1] Scam Detection
  console.log('\n' + BW('  [1] SCAM DETECTION  (20 pts)'));
  const det = scoreDetection(payload);
  result.scores.det = det.earned;
  console.log(`  ${det.detected ? TICK : CROSS} scamDetected = ${JSON.stringify(payload?.scamDetected ?? 'MISSING')}  →  ${det.detected ? G('+20 pts') : R('0 pts')}`);

  // [2] Intelligence Extraction
  console.log('\n' + BW(`  [2] INTELLIGENCE EXTRACTION  (40 pts — 10 pts per type)`));
  const intelScore = scoreIntelligence(payload?.extractedIntelligence, scenario.fakeData);
  result.scores.intel = intelScore.earned;
  result.intelResults = intelScore.results;

  for (const r of intelScore.results) {
    const pts = r.scored ? (r.found ? G(`+10 pts`) : R('0 pts — NOT FOUND')) : D('(not scored)');
    const mark = r.found ? TICK : (r.scored ? CROSS : D('·'));
    console.log(`  ${mark}  ${pad(r.arrayKey, 22)} ${D(`"${r.value}"`)}  →  ${pts}`);
    if (r.found && r.allValues.length > 0) {
      console.log(`       ${D('extracted: ' + r.allValues.map(v => `"${v}"`).join(', '))}`);
    } else if (!r.found && r.allValues.length > 0) {
      console.log(`       ${Y('array[' + r.allValues.length + ']: ' + r.allValues.map(v => `"${v}"`).join(', '))}`);
    } else if (!r.found) {
      console.log(`       ${D('array is empty []')}`);
    }
  }

  // otherInfo summary (not scored, context only)
  const otherInfo = payload?.extractedIntelligence?.otherInfo || [];
  if (otherInfo.length > 0) {
    console.log(`\n  ${D('·')}  ${D(pad('otherInfo (bonus context)', 22))}  ${CY(`${otherInfo.length} item(s) — not scored`)}`);
    for (const item of otherInfo.slice(0, 8)) {
      console.log(`       ${D('"' + item + '"')}`);
    }
    if (otherInfo.length > 8) console.log(`       ${D(`… and ${otherInfo.length - 8} more`)}`);
  }

  const intelCapNote = intelScore.raw > 40 ? D(` (${intelScore.raw} raw, capped at 40)`) : '';
  console.log(`  ${B('Subtotal:')} ${intelScore.earned >= 30 ? G(intelScore.earned + '/40') : Y(intelScore.earned + '/40')}${intelCapNote}`);

  // [3] Engagement Quality
  console.log('\n' + BW('  [3] ENGAGEMENT QUALITY  (20 pts)'));
  const eng = scoreEngagement(payload, history.length);
  result.scores.eng = eng.earned;
  for (const r of eng.rows) {
    console.log(`  ${r.ok ? TICK : CROSS}  ${pad(r.label, 36)} ${r.ok ? G('+' + r.pts + ' pts') : D('0 pts')}`);
  }
  console.log(D(`     duration: ${eng.dur}s  |  messages: ${eng.msgs}`));
  console.log(`  ${B('Subtotal:')} ${eng.earned >= 15 ? G(eng.earned + '/20') : Y(eng.earned + '/20')}`);

  // [4] Response Structure
  console.log('\n' + BW('  [4] RESPONSE STRUCTURE  (20 pts)'));

  const statusOk = result.turnResponseOk;
  console.log(`  ${statusOk ? TICK : CROSS}  ${pad('status: "success" in turn response', 36)} ${statusOk ? G('+5 pts') : R('0 pts')}`);

  const str = scoreStructure(payload);
  for (const f of str.fields) {
    if (f.pts === 0) continue;
    console.log(`  ${f.ok ? TICK : CROSS}  ${pad(f.label, 36)} ${f.ok ? G(`+${f.pts} pts`) : R(`0 pts`)}`);
  }

  const statusPts = statusOk ? 5 : 0;
  const strTotal  = statusPts + str.earned;
  result.scores.str = Math.min(strTotal, 20);

  console.log(`  ${B('Subtotal:')} ${result.scores.str >= 15 ? G(result.scores.str + '/20') : Y(result.scores.str + '/20')}`);

  // Response times
  console.log('\n' + BW('  [*] RESPONSE TIMES  (SLA, not scored)'));
  if (result.responseTimes.length > 0) {
    const tMin = Math.min(...result.responseTimes);
    const tMax = Math.max(...result.responseTimes);
    const tAvg = Math.round(result.responseTimes.reduce((a, b) => a + b, 0) / result.responseTimes.length);
    console.log(`  Min: ${tMin}ms  |  Avg: ${tAvg}ms  |  Max: ${tMax}ms`);
    console.log(tMax >= TIMEOUT_MS
      ? `  ${CROSS} ${R('At least one request hit the 30s timeout!')}`
      : `  ${TICK} All turns within 30s`);
  }

  // Inactivity report
  if (result.inactivityStop) {
    console.log('\n' + BW('  [*] INACTIVITY STOP'));
    console.log(`  ${Y('⚠')}  ${Y(`Scenario ended at turn ${result.crashedOnTurn} — scammer silent ${INACTIVITY_MS / 1000}s`)}`);
  }

  // Conversation quality
  console.log('\n' + BW('  [*] CONVERSATION QUALITY  (informational)'));
  const honeypotReplies = history.filter(m => m.sender === 'user').map(m => m.text);
  if (honeypotReplies.length === 0) {
    console.log(D('  No replies to evaluate.'));
  } else {
    const replyCounts = {};
    for (const r of honeypotReplies) {
      const key = r.trim().toLowerCase().slice(0, 80);
      replyCounts[key] = (replyCounts[key] || 0) + 1;
    }
    const repeated = Object.entries(replyCounts).filter(([, c]) => c > 1);

    const hasHinglish = honeypotReplies.some(r => /\b(yaar|na|hai|karo|bhai|toh|sahi|theek|accha|haan)\b/i.test(r));
    const hasHindi    = honeypotReplies.some(r => /[\u0900-\u097F]/.test(r));

    const avgLen = Math.round(honeypotReplies.reduce((s, r) => s + r.length, 0) / honeypotReplies.length);
    const lengthOk = avgLen >= 60 && avgLen <= 300;

    const emotionWords = /\b(wow|amazing|confused|scared|worried|excited|please|help|urgent|quickly|yaar|really|dont want|dont miss|happy|great|okay|oh no|oh wow)\b/i;
    const hasEmotion = honeypotReplies.filter(r => emotionWords.test(r)).length;
    const emotionRatio = Math.round((hasEmotion / honeypotReplies.length) * 100);

    const naturalFraming = /\b(just to be safe|want to make sure|in case|if something goes wrong|just checking|to confirm|to be sure|just want)\b/i;
    const naturalCount = honeypotReplies.filter(r => naturalFraming.test(r)).length;

    console.log(`  ${repeated.length === 0 ? TICK : Y('~')}  Repetition        : ${repeated.length === 0 ? G('No repeated replies') : Y(`${repeated.length} repeated reply(s) detected`)}`);
    console.log(`  ${lengthOk ? TICK : Y('~')}  Reply length      : ${avgLen} chars avg ${lengthOk ? G('(natural range 60-300)') : Y('(may be too short or too long)')}`);
    console.log(`  ${emotionRatio >= 50 ? TICK : Y('~')}  Emotional tone    : ${emotionRatio}% of replies show emotion ${emotionRatio >= 50 ? G('(good)') : Y('(may feel robotic)')}`);
    console.log(`  ${naturalCount > 0 ? TICK : Y('~')}  Natural framing   : ${naturalCount}/${honeypotReplies.length} replies use natural intel-request framing`);
    console.log(`  ${(hasHindi || hasHinglish) ? TICK : D('-')}  Language matching : ${hasHindi ? G('Hindi used') : hasHinglish ? G('Hinglish used') : D('English only')}`);

    if (repeated.length > 0) {
      for (const [key] of repeated.slice(0, 2)) {
        console.log(D(`     ↳ repeated: "${key.slice(0, 65)}..."`));
      }
    }

    const qualityScore = (repeated.length === 0 ? 1 : 0) + (lengthOk ? 1 : 0) + (emotionRatio >= 50 ? 1 : 0) + (naturalCount > 0 ? 1 : 0);
    const qualityLabel = qualityScore >= 4 ? G('REALISTIC') : qualityScore >= 3 ? CY('MOSTLY NATURAL') : qualityScore >= 2 ? Y('SOMEWHAT ROBOTIC') : R('ROBOTIC');
    console.log(`  Overall quality   : ${qualityLabel} (${qualityScore}/4 checks passed)`);
  }

  result.scores.total = result.scores.det + result.scores.intel + result.scores.eng + result.scores.str;

  console.log('\n' + hr('─'));
  const g = getGrade(result.scores.total);
  console.log(`  ${B('SCENARIO SCORE:')}  ${g.color}${C.bold}${result.scores.total}/100${C.reset}  ${g.color}${g.label}${C.reset}`);
  console.log(D(`  Det:${result.scores.det}/20  Intel:${result.scores.intel}/40  Eng:${result.scores.eng}/20  Str:${result.scores.str}/20`));
  console.log(hr('─'));

  return result;
}

// ─── Grand Summary ────────────────────────────────────────────────────────────
function printGrandSummary(results, scenarios) {
  console.log('\n\n' + hr('═'));
  console.log(BC('  🏆  FINAL HACKATHON SCORE'));
  console.log(D('  Formula: Final Score = Σ (Scenario_Score × Scenario_Weight / TotalWeight)'));
  console.log(hr('═'));

  const totalWeight = scenarios.reduce((s, sc) => s + (sc.weight ?? 10), 0);
  let finalScore = 0;

  console.log('');
  console.log(`  ${B(pad('Scenario', 28))} ${B(rpad('Score', 7))} ${B(rpad('Weight', 7))} ${B(rpad('Contrib', 8))} ${B('Status')}`);
  console.log(D('  ' + '─'.repeat(70)));

  for (const r of results) {
    const sc     = scenarios.find(s => s.scenarioId === r.scenarioId);
    const weight = (sc?.weight ?? 10) / totalWeight;
    const contrib = parseFloat((r.scores.total * weight).toFixed(2));
    finalScore += contrib;

    const status = r.crashed
      ? R(`CRASHED at T${r.crashedOnTurn}`)
      : r.timedOut
        ? R(`TIMEOUT at T${r.crashedOnTurn}`)
      : r.inactivityStop
        ? Y(`INACTIVITY T${r.crashedOnTurn}`)
        : !r.finalPayload
          ? Y('NO PAYLOAD')
          : `${getGrade(r.scores.total).color}${getGrade(r.scores.total).label}${C.reset}`;

    const sc2 = r.scores.total >= 70 ? C.green : r.scores.total >= 50 ? C.yellow : C.red;
    console.log(`  ${pad(r.scenarioId, 28)} ${sc2}${rpad(r.scores.total + '/100', 7)}${C.reset} ${D(rpad((weight * 100).toFixed(1) + '%', 7))} ${CY(rpad(contrib.toFixed(2), 8))} ${status}`);
    console.log(D(`  ${pad('', 28)} Det:${r.scores.det}/20  Intel:${r.scores.intel}/40  Eng:${r.scores.eng}/20  Str:${r.scores.str}/20`));

    const missing = (r.intelResults || []).filter(x => !x.found && x.scored);
    for (const m of missing) console.log(D(`  ${pad('', 28)}  ✗ ${m.arrayKey}: "${m.value}"`));
    console.log('');
  }

  console.log(D('  ' + '─'.repeat(70)));

  const g = getGrade(finalScore);
  console.log(`\n  ${B('FINAL SCORE  =  ')}${g.color}${C.bold}${finalScore.toFixed(1)} / 100${C.reset}  ${g.color}${g.label}${C.reset}`);

  console.log('\n' + hr('─'));
  console.log(BW('  REQUIREMENTS CHECKLIST  (disqualifying if failed)'));
  console.log(hr('─'));

  const chk = [
    { label: 'Endpoint publicly accessible',          ok: results.some(r => r.checks.reachable) },
    { label: 'API returns HTTP 200',                  ok: results.some(r => r.checks.returns200) },
    { label: 'Response has reply field',              ok: results.some(r => r.checks.hasReplyField) },
    { label: 'Turn response includes status field',   ok: results.some(r => r.turnResponseOk) },
    { label: 'All responses under 30s',               ok: results.every(r => r.checks.allUnder30s) },
  ];

  for (const c of chk) console.log(`  ${c.ok ? TICK : CROSS}  ${c.label}`);

  const failed = chk.filter(c => !c.ok).length;
  console.log('\n' + hr('─'));

  if (failed === 0) {
    console.log(G(`  ✅  All checks passed. Final score: ${finalScore.toFixed(1)}/100. Ready for submission.`));
  } else {
    console.log(R(`  ❌  ${failed} requirement(s) failed. Fix before submitting.`));
  }

  console.log(hr('═') + '\n');
  return { finalScore, failed };
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  try {
    await startCallbackServer();
  } catch (err) {
    console.error(R(`\n  ❌ Failed to start callback server: ${err.message}`));
    process.exit(1);
  }

  const localIP     = getLocalIP();
  const callbackUrl = `http://${localIP}:${LISTEN_PORT}/callback`;

  console.log('\n' + hr('═'));
  console.log(BC('  🍯  HONEYTRAP CLI TESTER'));
  console.log(D(`  Endpoint    : ${ENDPOINT}`));
  console.log(D(`  API Key     : ${API_KEY ? '***' + API_KEY.slice(-4) : '(none)'}`));
  console.log(D(`  Timeout     : ${TIMEOUT_MS / 1000}s/request  |  Turn delay: ${TURN_DELAY_MS}ms`));
  console.log(D(`  Inactivity  : ${INACTIVITY_MS > 0 ? INACTIVITY_MS / 1000 + 's  (--inactivity <ms> to change)' : 'disabled'}`));
  console.log(D(`  Scenarios   : ${ONLY ? ONLY : `All ${SCENARIOS.length}`}${VERBOSE ? '  |  VERBOSE' : ''}`));
  console.log('');
  console.log(G('  ┌─────────────────────────────────────────────────────────┐'));
  console.log(G('  │  CALLBACK SERVER READY                                  │'));
  console.log(G(`  │  URL: ${callbackUrl.padEnd(51)}│`));
  console.log(G('  │  Set this as FINAL_CALLBACK_URL in your honeypot env    │'));
  console.log(G('  └─────────────────────────────────────────────────────────┘'));
  console.log(hr('═'));

  const toRun = ONLY ? SCENARIOS.filter(s => s.scenarioId === ONLY) : SCENARIOS;

  if (!toRun.length) {
    console.error(R(`\n  No scenario matching "${ONLY}". Available: ${SCENARIOS.map(s => s.scenarioId).join(', ')}`));
    await stopCallbackServer();
    process.exit(1);
  }

  const results = [];
  for (const sc of toRun) {
    results.push(await runScenario(sc, callbackUrl));
    if (toRun.length > 1) await sleep(1200);
  }

  await stopCallbackServer();

  const summary = printGrandSummary(results, toRun);
  process.exit(summary.failed > 0 ? 1 : 0);
}

main().catch(async err => {
  console.error(R(`\nUnexpected error: ${err.message}`));
  console.error(err.stack);
  await stopCallbackServer();
  process.exit(1);
});