# OpenDCHub

A Linux/Unix Direct Connect hub using the NMDC protocol. Pure protocol adapter — connects DC clients and communicates with [odch-gateway](https://github.com/typhonius/odch-gateway) via Unix domain socket.

## Features

- NMDC protocol with TLS support
- Unix domain socket IPC with gateway (length-prefixed JSON)
- Multi-process architecture (fork-per-N-users)
- No embedded scripting, no database, no flat file data

## Architecture

```
DC Clients ←→ opendchub ←→ odch-gateway (Unix socket, JSON)
                                │
                           PostgreSQL
```

The hub accepts NMDC client connections and forwards events (chat, join, quit, kick, myinfo) to the gateway. The gateway handles all logic: bans, gags, registration, bot commands, webhooks.

## Building

```bash
automake --add-missing --copy 2>/dev/null || true
autoreconf -fi 2>/dev/null || autoconf -f
./configure --enable-ssl
make
```

Dependencies: `build-essential autoconf automake libcrypt-dev libssl-dev`

## Configuration

`~/.opendchub/config`:

```
hub_name = "My Hub"
listening_port = 4012
tls_port = 4013
tls_cert_file = "/path/to/fullchain.pem"
tls_key_file = "/path/to/privkey.pem"
json_socket_path = "/opt/opendchub/gateway.sock"
json_socket_secret = "shared_secret_here"
max_users = 500
```

## Deployment

```bash
# Install .deb (from GitHub releases)
sudo dpkg -i opendchub_*.deb

# Or use odch-gateway init to generate all configs:
odch-gateway init --hub-port 4012
```

## Related

- [odch-gateway](https://github.com/typhonius/odch-gateway) — REST API, database, bot commands, admin UI
- [odchbot](https://github.com/typhonius/odchbot) — Optional standalone bot (fun commands, plugins)
