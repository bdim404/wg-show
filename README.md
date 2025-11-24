# wg-show

A lightweight WireGuard utility that enhances `wg show` output with human-readable peer nicknames, groups, and maintainers from your configuration files.

## Features

- Transparent wrapper around the native `wg` command
- Displays peer nicknames, groups, and maintainers alongside standard output
- Reads metadata from configuration file comments
- Filter peers by maintainer or group
- Sort peers by handshake time (ascending or descending)
- Table view mode for better overview
- Zero configuration required

## Installation

### GitHub

Download the binary for your platform from [releases](https://github.com/bdim404/wg-show/releases) and place it in your PATH:

```bash
sudo mv wg-show /usr/local/bin/
sudo chmod +x /usr/local/bin/wg-show
```

Or build from source:

```bash
go build -o wg-show main.go
```

### Nix flake

```bash
nix profile add github:bdim404/wg-show
```

## Usage

Use it exactly like the standard `wg show` command:

```bash
wg-show
wg-show wg0
wg-show wg0 dump
```

### Additional Options

```bash
wg-show -v                                    # Show version
wg-show --show-table                          # Display output in table format
wg-show --filter-maintainer alice             # Show only peers maintained by alice
wg-show --filter-group mobile                 # Show only peers in mobile group
wg-show --sort-handshake asc                  # Sort peers by handshake time (oldest first)
wg-show --sort-handshake desc                 # Sort peers by handshake time (newest first)
```

You can combine multiple options:

```bash
wg-show --show-table --filter-maintainer alice --sort-handshake asc
```

### Configuration

Add nicknames, groups, and maintainers to peers using comments in your WireGuard config (`/etc/wireguard/wg0.conf`):

```ini
[Interface]
PrivateKey = ...

# laptop
## Alice's Laptop (@alice)
[Peer]
PublicKey = abc123...
AllowedIPs = 10.0.0.2/32

# mobile
## Bob's Phone (@bob)
[Peer]
PublicKey = def456...
AllowedIPs = 10.0.0.3/32

# server
## Production Server
[Peer]
PublicKey = ghi789...
AllowedIPs = 10.0.0.4/32
```

Comment format:
- `#` single hash = group name
- `##` double hash = peer nickname
- `(@username)` at the end of nickname = maintainer

## Examples

### Standard Output

**Standard `wg show`:**
```
peer: abc123...
  endpoint: 1.2.3.4:51820
  allowed ips: 10.0.0.2/32
```

**With `wg-show`:**
```
peer: abc123...
  nickname: Alice's Laptop
  maintainer: alice
  group: laptop
  endpoint: 1.2.3.4:51820
  allowed ips: 10.0.0.2/32
```

### Table View

**With `wg-show --show-table`:**
```
Interface: wg0
Public Key: xyz...
Listening Port: 51820

Peers:
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
Nickname             Maintainer      Group           Endpoint                       Handshake
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
Alice's Laptop       alice           laptop          1.2.3.4:51820                  2 minutes, 30 seconds ago
  Allowed IPs: 10.0.0.2/32
  Transfer: 5.12 GiB received, 1.23 GiB sent

Bob's Phone          bob             mobile          5.6.7.8:41234                  1 hour, 15 minutes ago
  Allowed IPs: 10.0.0.3/32
  Transfer: 234.56 MiB received, 89.12 MiB sent
```
