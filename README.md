# OpenDCHub

A Linux/Unix version of the Direct Connect hub, using the NMDC protocol.

## Building

```bash
autoreconf -fi
./configure
make
sudo make install
```

### Requirements

- GCC (tested with GCC 10+)
- Perl + libperl-dev (for scripting support; use `--disable-perl` to skip)
- autoconf, automake (for building from source)

## Running

```bash
opendchub
```

On first run you'll be prompted for a listening port and admin password. Configuration is stored in `~/.opendchub/`.

## Bot

OpenDCHub supports Perl scripting. See [ODCHBot](https://github.com/typhonius/odchbot) for a full-featured bot.

## License

GNU General Public License v2. See [COPYING](COPYING).
