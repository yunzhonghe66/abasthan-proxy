// Minimal forward proxy (HTTP + CONNECT), zero dependencies.
// Auth: Basic auth, user PROXY_USER (default "user"), password PROXY_PASS.
// If PROXY_PASS is unset the proxy is open (not recommended).
// GET / is a public health endpoint (no auth) for platform health checks.
const http = require('http');
const https = require('https');
const net = require('net');

const PORT = parseInt(process.env.PORT || '3000', 10);
const PROXY_USER = process.env.PROXY_USER || 'user';
const PROXY_PASS = process.env.PROXY_PASS || '';

function authed(req) {
  if (!PROXY_PASS) return true;
  const h = req.headers['proxy-authorization'] || '';
  if (!h.startsWith('Basic ')) return false;
  const [u, p] = Buffer.from(h.slice(6), 'base64').toString('utf8').split(':');
  return u === PROXY_USER && p === PROXY_PASS;
}

function needAuth(res) {
  res.writeHead(407, { 'Proxy-Authenticate': 'Basic realm="proxy"' });
  res.end('Proxy authentication required');
}

const server = http.createServer((req, res) => {
  if (req.url === '/' || req.url === '/health') {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('ok');
    return;
  }
  if (!authed(req)) return needAuth(res);
  let target;
  try {
    target = new URL(req.url);
  } catch {
    res.writeHead(400);
    res.end('bad url');
    return;
  }
  const lib = target.protocol === 'https:' ? https : http;
  const up = lib.request({
    protocol: target.protocol,
    hostname: target.hostname,
    port: target.port || (target.protocol === 'https:' ? 443 : 80),
    method: req.method,
    path: target.pathname + target.search,
    headers: { ...req.headers, host: target.host },
  }, (upRes) => {
    res.writeHead(upRes.statusCode, upRes.headers);
    upRes.pipe(res);
  });
  up.on('error', () => { res.writeHead(502); res.end('bad gateway'); });
  req.pipe(up);
});

server.on('connect', (req, socket, head) => {
  if (!authed(req)) {
    socket.end('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="proxy"\r\n\r\n');
    return;
  }
  const [host, port] = req.url.split(':');
  const up = net.connect(parseInt(port || '443', 10), host, () => {
    socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head && head.length) up.write(head);
    socket.pipe(up);
    up.pipe(socket);
  });
  up.on('error', () => socket.end());
  socket.on('error', () => up.end());
});

server.listen(PORT, () => {
  console.log(`proxy listening on ${PORT} (auth ${PROXY_PASS ? 'on' : 'OFF - open proxy'})`);
});
