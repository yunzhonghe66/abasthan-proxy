// Fetch-style proxy (zero dependencies).
//
// Abasthan's gateway blocks classic forward-proxy traffic (CONNECT -> 400,
// absolute-form requests -> 403), so this service exposes a plain web API
// instead: it fetches a URL server-side and returns the response.
//
//   GET  /                        health check, returns "ok" (no auth)
//   GET  /fetch?url=<url>         fetch a URL (Basic auth)
//   POST /fetch  {"url","method","headers","body"}   (Basic auth)
//
// Auth: Authorization: Basic base64(PROXY_USER:PROXY_PASS).
// If PROXY_PASS is unset the API is open (not recommended).
//
// Guards: http(s) only, no localhost/private/link-local targets (SSRF),
// 20s timeout, 10 MB response cap.
const http = require('http');
const https = require('https');
const dns = require('dns').promises;
const net = require('net');

const PORT = parseInt(process.env.PORT || '3000', 10);
const PROXY_USER = process.env.PROXY_USER || 'user';
const PROXY_PASS = process.env.PROXY_PASS || '';
const TIMEOUT_MS = 20000;
const MAX_BYTES = 10 * 1024 * 1024;

function authed(req) {
  if (!PROXY_PASS) return true;
  const h = req.headers['authorization'] || '';
  if (!h.startsWith('Basic ')) return false;
  const [u, p] = Buffer.from(h.slice(6), 'base64').toString('utf8').split(':');
  return u === PROXY_USER && p === PROXY_PASS;
}

function needAuth(res) {
  res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="fetch-proxy"' });
  res.end('authentication required');
}

function isPrivateIP(ip) {
  if (net.isIP(ip) === 4) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 169 && b === 254);
  }
  if (net.isIP(ip) === 6) {
    const l = ip.toLowerCase();
    return l === '::1' || l.startsWith('fe8') || l.startsWith('fe9') ||
      l.startsWith('fea') || l.startsWith('feb') ||
      l.startsWith('fc') || l.startsWith('fd');
  }
  return false;
}

async function assertPublicTarget(urlStr) {
  let u;
  try {
    u = new URL(urlStr);
  } catch {
    throw new Error('bad url');
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new Error('only http(s) allowed');
  }
  const host = u.hostname.toLowerCase();
  if (host === 'localhost' || host.endsWith('.localhost')) {
    throw new Error('blocked target');
  }
  if (net.isIP(host)) {
    if (isPrivateIP(host)) throw new Error('blocked target');
    return u;
  }
  let addrs;
  try {
    addrs = await dns.lookup(host, { all: true });
  } catch {
    throw new Error('cannot resolve target');
  }
  if (!addrs.length || addrs.some((a) => isPrivateIP(a.address))) {
    throw new Error('blocked target');
  }
  return u;
}

function fetchUpstream(u, opts) {
  return new Promise((resolve, reject) => {
    const lib = u.protocol === 'https:' ? https : http;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
    const req = lib.request({
      protocol: u.protocol,
      hostname: u.hostname,
      port: u.port || (u.protocol === 'https:' ? 443 : 80),
      method: opts.method || 'GET',
      path: u.pathname + u.search,
      headers: { ...(opts.headers || {}), host: u.host },
      signal: ctrl.signal,
    }, (upRes) => {
      const chunks = [];
      let total = 0;
      let tooBig = false;
      upRes.on('data', (c) => {
        total += c.length;
        if (total > MAX_BYTES) {
          tooBig = true;
          req.destroy();
        } else {
          chunks.push(c);
        }
      });
      upRes.on('end', () => {
        clearTimeout(timer);
        if (tooBig) return reject(new Error('response too large'));
        resolve({ status: upRes.statusCode, headers: upRes.headers, body: Buffer.concat(chunks) });
      });
      upRes.on('error', (e) => { clearTimeout(timer); reject(e); });
    });
    req.on('error', (e) => { clearTimeout(timer); reject(e); });
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
]);

function sendUpstream(res, result) {
  const headers = {};
  for (const [k, v] of Object.entries(result.headers)) {
    if (!HOP_BY_HOP.has(k.toLowerCase())) headers[k] = v;
  }
  res.writeHead(result.status, headers);
  res.end(result.body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (c) => {
      total += c.length;
      if (total > 1024 * 1024) return reject(new Error('request too large'));
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, 'http://x');
    if (u.pathname === '/' || u.pathname === '/health') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('ok');
      return;
    }
    if (u.pathname !== '/fetch') {
      res.writeHead(404);
      res.end('not found');
      return;
    }
    if (!authed(req)) return needAuth(res);
    let target;
    let opts = {};
    if (req.method === 'GET') {
      target = u.searchParams.get('url');
      if (!target) {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'missing ?url=' }));
        return;
      }
    } else if (req.method === 'POST') {
      const raw = await readBody(req);
      let payload;
      try {
        payload = JSON.parse(raw || '{}');
      } catch {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid JSON' }));
        return;
      }
      target = payload.url;
      if (!target) {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'missing url' }));
        return;
      }
      opts = {
        method: payload.method || 'GET',
        headers: payload.headers || {},
        body: payload.body,
      };
    } else {
      res.writeHead(405);
      res.end('method not allowed');
      return;
    }
    const targetUrl = await assertPublicTarget(target);
    const result = await fetchUpstream(targetUrl, opts);
    sendUpstream(res, result);
  } catch (e) {
    const msg = String((e && e.message) || e);
    const code = /blocked|bad url|only http|resolve|too large/.test(msg) ? 400 : 502;
    res.writeHead(code, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: msg }));
  }
});

server.listen(PORT, () => {
  console.log(`fetch-proxy listening on ${PORT} (auth ${PROXY_PASS ? 'on' : 'OFF - open proxy'})`);
});
