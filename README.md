# mrrowisp

A [Wisp](https://github.com/MercuryWorkshop/wisp-protocol) server written in Go,
with a Node.js wrapper for spawning and load-balancing across multiple
worker processes.

mrrowisp supports Wisp v1, v2, and optionally Twisp (PTY over Wisp). It includes
flood protection, per-source/per-destination rate limiting, IP scoring, an egress
allow/deny policy, a DNS cache, and reverse-proxy IP parsing.

## Features

- Wisp v1 and v2 (`enableV2`) over WebSocket
- Optional Twisp (`enableTwisp`)
- TCP and UDP stream support (`allowTCP`, `allowUDP`)
- Hostname/port allow and block lists
- Direct IP, private IP, and loopback egress controls
- Flood protection: per-source, per-destination, SYN flood detection
- IP reputation with on-disk persistence and decay
- Bandwidth and connection rate limits per IP
- Optional password authentication
- Optional upstream HTTP/SOCKS proxy
- Reverse-proxy real-IP parsing (`CF-Connecting-IP`, `X-Forwarded-For`, ...)
- Optional static file serving alongside the `/wisp` endpoint

## Installing

### From source (Go)

Requires Go 1.25+.

```sh
go build -o mrrowisp main.go
```

Or build cross-platform binaries into `./bin/`:

```sh
./build.sh
```

### Docker

```sh
docker build -t mrrowisp .
docker run -p 6001:6001 -v $(pwd)/config.json:/app/config.json mrrowisp
```

### npm / pnpm (Node.js wrapper)

```sh
pnpm install mrrowisp
```

## Running the standalone server

```sh
./mrrowisp --config config.json
```

Flags:

- `--config <path|json>` – path to a config file or an inline JSON string
- `--port <n>` – override the port from config
- `--allow-loopback` – override `allowLoopbackIPs`

If no `--config` is supplied, the built-in defaults from
`wisp.DefaultConfig()` are used.

See `example.config.json` for the full list of supported options.

## Using the Node.js wrapper

The wrapper spawns one or more `mrrowisp` Go processes and the built-in load
balancing routes incoming WebSocket upgrades across them.

```ts
import { Mrrowisp } from "mrrowisp";
import { createServer } from "node:http";

const wisp = new Mrrowisp({ port: 6001, logLevel: "info" });
await wisp.start(4); // spawn 4 workers, which would route to 6001, 6002, 6003, and 6004 or similar automatically

const server = createServer();
server.on("upgrade", (req, socket, head) => wisp.route(req, socket, head));
server.listen(8080);
```

API:

- `new Mrrowisp(partialConfig?)` – overrides merged onto defaults loaded from
  `dist/config.json`
- `start(count = 1)` – spawn N worker processes, each on its own port
- `route(req, socket, head)` – proxy a WebSocket upgrade to the next worker
- `stop()` – `SIGTERM` all workers
- `kill()` – `SIGKILL` all workers

## Configuration

The full schema lives in `example.config.json` and `wisp/config.go`. Featured
keys:

| Key | Default | Description |
| --- | --- | --- |
| `port` | `6001` | TCP port to listen on |
| `allowTCP` / `allowUDP` | `true` | Permit TCP/UDP stream types |
| `allowDirectIP` | `false` | Allow connecting to literal IPs |
| `allowPrivateIPs` | `false` | Allow RFC1918 destinations |
| `allowLoopbackIPs` | `false` | Allow loopback destinations |
| `enableV2` | `true` | Enable Wisp v2 extensions |
| `enableTwisp` | `false` | Enable Twisp |
| `passwordAuth(Required)` | `false` | Password auth |
| `parseRealIP` | `true` | Honor `trustedHeaders` from `trustedProxies` |
| `bandwidthLimitKbps` | `0` | Per-IP bandwidth limit (0 = off) |
| `floodProtection` | enabled | See `example.config.json` |
| `reputation` | enabled | Persistent IP reputation scoring |

## Credits

- [soap phia](https://github.com/sylvieisnton/) – Writing mrrowisp
- [Amplify](https://github.com/not-amplify/) – Adding protections against flooding

## License

BSD-3-Clause. See [LICENSE](./LICENSE).
