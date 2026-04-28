# OpenDCHub

C implementation of a Direct Connect hub (NMDC protocol). Pure protocol adapter — no scripting, no database, no logic. All moderation and data managed by the gateway.

## Building

```bash
automake --add-missing --copy 2>/dev/null || true
autoreconf -fi 2>/dev/null || autoconf -f
./configure --enable-ssl
make
```

Dependencies: build-essential, autoconf, automake, libcrypt-dev, libssl-dev.

## Key source files

- `src/main.c` — Main loop, fork model, signal handling
- `src/commands.c` — NMDC command handlers (chat, kick, MyINFO, validate_nick)
- `src/network.c` — Poll loop, socket management, send_to_humans/send_to_user
- `src/json_socket.c` — Unix domain socket IPC with gateway (JSON protocol)
- `src/cJSON.c` — Vendored JSON parser

## Architecture

The hub accepts NMDC client connections and forwards all events to the gateway via a Unix domain socket speaking length-prefixed JSON. The gateway decides everything: bans, gags, registration, moderation.

```
DC Clients ←→ opendchub ←→ gateway (Unix socket, JSON)
```

The hub does NOT:
- Check bans, gags, or passwords (gateway handles this)
- Store any data (no flat files, no database)
- Run scripts (no embedded Perl)

## Config

`~/.opendchub/config` — hub name, ports, TLS certs, JSON socket path + secret.

## Releases

Tag `v*` triggers `.github/workflows/release.yml` which builds a `.deb` package.

## Server

- Binary: `/usr/local/bin/opendchub`
- Service: `opendchub.service` (systemd, `-d` flag for foreground)
- Config: `/opt/opendchub/.opendchub/config`
- Socket: `/opt/opendchub/gateway.sock`
