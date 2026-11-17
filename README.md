# abasthan-proxy

Minimal authenticated forward proxy (HTTP + `CONNECT`), zero dependencies,
plain Node.js. Built to test deploying a Node.js service on Abasthan.

## Run

```sh
node app.js
```

Listens on `$PORT` (default 3000).

## Auth

- `PROXY_USER` (default `user`)
- `PROXY_PASS` — if unset, the proxy is open (not recommended)

Clients authenticate with standard Basic proxy auth, e.g.:

```sh
curl -x http://user:PASS@host:port https://example.com
```

`GET /` is a public health endpoint returning `ok` (no auth), for platform
health checks.
