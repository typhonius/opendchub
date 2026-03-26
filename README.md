# OpenDCHub

A Linux/Unix Direct Connect hub using the NMDC protocol. Supports TLS, Perl scripting, bcrypt passwords, admin commands, and real-time event streaming.

## Features

- **NMDC protocol** hub with TLS support
- **Perl scripting** for bots and automation
- **Bcrypt password hashing** with automatic DES-to-bcrypt migration
- **Admin port** with `$GetStatus`, `$GetUserList`, and real-time event stream
- **Systemd** service file included
- **Config hot-reload** via SIGHUP (hub name, MOTD, max users, etc.)
- **Structured logging** — text (default) or JSON format
- **Pre-built .deb packages** in [GitHub Releases](https://github.com/typhonius/opendchub/releases)

## Installation

### From .deb package (Debian/Ubuntu)

Download the latest `.deb` from [Releases](https://github.com/typhonius/opendchub/releases):

```bash
curl -LO https://github.com/typhonius/opendchub/releases/latest/download/opendchub_0.11.1-1_amd64.deb
sudo dpkg -i opendchub_0.11.1-1_amd64.deb
```

### From source

```bash
autoreconf -fi
./configure
make
sudo make install
```

#### Requirements

- GCC (tested with GCC 10+)
- Perl + libperl-dev (for scripting support; use `--disable-perl` to skip)
- autoconf, automake (for building from source)

#### Build options

```bash
./configure --disable-perl     # Build without Perl scripting
./configure --with-bcrypt      # Enable bcrypt password hashing (recommended)
```

## Running

```bash
opendchub
```

On first run you'll be prompted for a listening port and admin password. Configuration is stored in `~/.opendchub/`.

### Systemd

A service file is included for systemd-based systems:

```bash
sudo cp opendchub.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now opendchub
```

Reload configuration without restarting:

```bash
sudo systemctl reload opendchub   # sends SIGHUP
```

## Configuration

Settings can be changed at runtime via the admin port using `$SetVar`:

| Setting | Description | Reloadable |
|---------|-------------|:----------:|
| `hub_name` | Hub display name | Yes |
| `hub_description` | Hub description | Yes |
| `min_share` | Minimum share requirement | Yes |
| `max_users` | Maximum connected users | Yes |
| `hub_full_mess` | Message shown when hub is full | Yes |
| `redirect_host` | Redirect address when full | Yes |
| `log_format` | `text` (default) or `json` | Yes |
| `log_file` | Path to log file (relative to config dir) | Yes |
| `listening_port` | NMDC listen port | No (restart) |
| `admin_port` | Admin port | No (restart) |

## Admin commands

Connect to the admin port (default 53696) to use these commands:

| Command | Description |
|---------|-------------|
| `$GetStatus` | Returns hub status (name, users, share, uptime, ports) |
| `$GetUserList` | Returns all connected users with IP, share, type |
| `$Kick <nick>` | Kick a user |
| `$AddBanEntry <nick>` | Ban a user |
| `$RemoveBanEntry <nick>` | Unban a user |
| `$SetVar <key>=<value>` | Change a config setting |

### Event stream

When `admin_events` is enabled, admin connections receive real-time hub events:

```
$Event JOIN <nick>|
$Event QUIT <nick>|
$Event CHAT <nick> <message>|
$Event MYINFO <nick> <description>$ $<speed>$<email>$<share>$|
$Event SEARCH <nick> <pattern>|
$Event KICK <nick> <by>|
```

This enables the [odch-gateway](https://github.com/typhonius/odch-gateway) REST/WebSocket API sidecar.

## Bot

OpenDCHub supports Perl scripting. See [ODCHBot](https://github.com/typhonius/odchbot) for a full-featured bot with trivia, achievements, ranks, moderation, and 20+ commands.

## API gateway

For REST API, WebSocket, and webhook access to the hub, see [odch-gateway](https://github.com/typhonius/odch-gateway) — a Rust sidecar that connects via the admin port and NMDC protocol.

## License

GNU General Public License v2. See [COPYING](COPYING).
