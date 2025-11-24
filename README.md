# wg-show

A lightweight WireGuard utility that enhances `wg show` output with human-readable peer nicknames and groups from your configuration files.

## Features

- Transparent wrapper around the native `wg` command
- Displays peer nicknames and groups alongside standard output
- Reads metadata from configuration file comments
- Zero configuration required

## Installation

Download the binary for your platform from [releases](https://github.com/bdim404/wg-show/releases) and place it in your PATH:

```bash
sudo mv wg-show /usr/local/bin/
sudo chmod +x /usr/local/bin/wg-show
```

Or build from source:

```bash
go build -o wg-show main.go
```

## Usage

Use it exactly like the standard `wg show` command:

```bash
wg-show
wg-show wg0
wg-show wg0 dump
```

### Configuration

Add nicknames and groups to peers using comments in your WireGuard config (`/etc/wireguard/wg0.conf`):

```ini
[Interface]
PrivateKey = ...

# laptop
## Alice's Laptop
[Peer]
PublicKey = abc123...
AllowedIPs = 10.0.0.2/32

# mobile
## Bob's Phone
[Peer]
PublicKey = def456...
AllowedIPs = 10.0.0.3/32
```

- `#` single hash = group name
- `##` double hash = peer nickname

## Example

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
  group: laptop
  endpoint: 1.2.3.4:51820
  allowed ips: 10.0.0.2/32
```
