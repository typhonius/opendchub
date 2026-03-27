# OpenDCHub

C implementation of a Direct Connect hub (NMDC protocol).

## Repo

- **GitHub**: github.com/typhonius/opendchub
- **Main branch**: `master`
- **Remote**: HTTPS

## Building

```bash
# Local (requires autoconf, automake, perl, libperl-dev, libssl-dev, libcrypt-dev)
automake --add-missing --copy 2>/dev/null || true
autoreconf -fi 2>/dev/null || autoconf -f
./configure --enable-ssl
make

# Docker (build + integration tests)
docker build -f Dockerfile.test -t odch-test .
docker run --rm odch-test
```

## Key source files

- `src/main.c` — Command dispatcher (`handle_command()`), admin port, event stream
- `src/main.h` — User types, structs, constants
- `src/commands.c` — Command implementations (kick, ban, admin auth)
- `src/network.c` — `send_to_humans()`, `send_to_non_humans()`, `send_to_user()`
- `src/xs_functions.c` — Perl XS bindings (data_to_all, data_to_user, kick_user, etc.)

## User types (bitmask)

```
UNKEYED=0x1  NON_LOGGED=0x2  REGULAR=0x4  REGISTERED=0x8
OP=0x10  OP_ADMIN=0x20  ADMIN=0x40  FORKED=0x80
LINKED=0x100  SCRIPT=0x200  NON_LOGGED_ADM=0x400
```

## Admin port

Default port `0xD1C0` (53696), localhost only. Commands:
- `$AdminPassword <pass>|` — authenticate
- `$GetStatus|` — hub status JSON
- `$GetUserList|` — connected user list
- `$Kick <nick>|` — kick user
- `$AddBanEntry <nick>|` / `$RemoveBanEntry <nick>|`
- `$AddGagEntry <nick>|` / `$RemoveGagEntry <nick>|`
- `$DataToAll <data>|` — broadcast raw data to all human clients (ADMIN, SCRIPT, FORKED)
- `$Event` stream — JOIN, QUIT, CHAT, KICK, MYINFO, SEARCH events

## Multi-process architecture

Parent process + forked child processes + script process. Commands dispatched via `handle_command()` must emit `$Event` from forwarding paths, not just the origin process.

## Releases

Tag `v*` triggers `.github/workflows/release.yml` which builds a `.deb` package (Ubuntu 24.04, libperl5.38). The version in `configure.in` is stamped from the git tag at build time.

```bash
git tag v0.12.1 && git push origin v0.12.1
```

## Testing

```bash
docker build -f Dockerfile.test -t odch-test . && docker run --rm odch-test
```

Tests: `test/run.sh` (hub lifecycle) + `test/dc_client.pl` (NMDC protocol).

## Server

- Binary: `/usr/local/bin/opendchub` (installed via .deb)
- Service: `opendchub.service` (systemd, user `opendchub`)
- Working dir: `/opt/opendchub`
- Config: `/opt/opendchub/.opendchub/config`
- Scripts: `/opt/opendchub/.opendchub/scripts/` (odchbot checkout)
- Deploy: download .deb from GitHub release, `sudo dpkg -i opendchub_*.deb`, restart service
