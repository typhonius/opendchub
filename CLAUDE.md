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
- `src/json_socket.c` — Unix domain socket IPC with gateway (JSON protocol), virtual user management
- `src/cJSON.c` — Vendored JSON parser

## Architecture

The hub accepts NMDC client connections and forwards all events to the gateway via a Unix domain socket speaking length-prefixed JSON. The gateway decides everything: bans, gags, registration, moderation. The gateway also registers virtual users that appear in the hub's user list without real NMDC connections.

```
DC Clients ←→ opendchub ←→ gateway (Unix socket, JSON)
                              ↕
                     virtual users (Dragon, OPChat)
```

### JSON socket commands (gateway → hub)

Core: `kick`, `send_all`, `send_to`, `send_raw`, `send_raw_to`, `get_status`, `get_user_list`, `register_user`, `unregister_user`, `purge_stale`

Virtual users: `add_virtual_user`, `remove_virtual_user`, `send_chat_as`, `send_pm_as`, `send_to_as`

- `send_raw` broadcasts a verbatim NMDC string to all users (no sanitization). `send_raw_to` sends to a specific user. Used by the gateway to echo chat, send greetings, and set topic.
- `purge_stale` removes users stuck in the NMDC handshake (UNKEYED/NON_LOGGED). Called by the gateway's periodic MaintenanceTick.

### JSON socket events (hub → gateway)

`chat`, `user_join`, `user_quit`, `myinfo`, `kick`, `search`, `pm` (PMs to virtual users)

### Chat flow

Chat messages follow a gateway-mediated pattern: user sends NMDC chat → hub forwards to gateway via `json_event_chat` → gateway checks gag, decides → sends `send_raw` back to broadcast (or drops if gagged). The hub does NOT broadcast chat directly.

### Main loop

Poll/select with 1-second timeout (`network.c`). No SIGALRM — periodic maintenance (stale connection purge) is driven by the gateway sending `purge_stale` commands.

The hub does NOT:
- Check bans, gags, or passwords (gateway handles this)
- Broadcast chat directly (gateway mediates all chat via send_raw)
- Send greetings or topic (gateway sends via send_raw_to on user_join)
- Store any data (no flat files, no database)
- Run scripts (no embedded Perl)
- Run timers (gateway's MaintenanceTick drives periodic work)

## Config

`~/.opendchub/config` — hub name, ports, TLS certs, JSON socket path + secret.

## Releases

Tag `v*` triggers `.github/workflows/release.yml` which builds a `.deb` package.

## Server

- Binary: `/usr/local/bin/opendchub`
- Service: `opendchub.service` (systemd, `-d` flag for foreground)
- Config: `/opt/opendchub/.opendchub/config`
- Socket: `/opt/opendchub/gateway.sock`
