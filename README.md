# abasthan-proxy

Fetch-style proxy (zero dependencies, plain Node.js). Built to test deploying
a Node.js service on Abasthan.

Abasthan's gateway blocks classic forward-proxy traffic (CONNECT gets a 400,
absolute-form requests get a 403), so this service exposes a plain web API
instead: it fetches a URL server-side and returns the response.

## Run

```sh
node app.js
```

Listens on `$PORT` (default 3000).

## Auth

- `PROXY_USER` (default `user`)
- `PROXY_PASS` — if unset, the API is open (not recommended)

Clients authenticate with standard Basic auth (`Authorization: Basic ...`).

## API

```sh
# Simple GET
curl -u user:PASS "https://HOST/fetch?url=https://example.com"

# POST with options
curl -u user:PASS -X POST https://HOST/fetch \
  -H 'content-type: application/json' \
  -d '{"url": "https://example.com", "method": "GET"}'
```

`GET /` is a public health endpoint returning `ok` (no auth), for platform
health checks. Targets are limited to public http(s) URLs (no localhost or
private IPs), with a 20s timeout and a 10 MB response cap.
