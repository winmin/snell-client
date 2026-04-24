# snell-client

A lightweight Snell v5 proxy client written in Rust, providing a local SOCKS5 interface.

## Features

- Snell v5 protocol support (reverse-engineered)
- AES-128-GCM AEAD encryption with Argon2id key derivation
- Local SOCKS5 proxy interface (supports CONNECT with IPv4/IPv6/domain)
- Async I/O with Tokio
- Zero-copy in-place encryption/decryption
- Secure key material handling with zeroize

## Protocol Details

The Snell v5 protocol uses:

| Component | Detail |
|-----------|--------|
| Key Derivation | Argon2id (t=3, m=8KiB, p=1) |
| AEAD Cipher | AES-128-GCM (16-byte key from 32-byte derived key) |
| Salt | 16 bytes per direction, each side derives independent keys |
| Frame Header | 7 bytes: `[type(1)] [reserved(2)] [padding_len(2 BE)] [payload_len(2 BE)]` |
| Wire Format | `[enc_header(23)] [padding(N)] [enc_payload(M+16)]` with byte interleave obfuscation |

## Build

```bash
cargo build --release
```

The binary will be at `target/release/snell-client`.

## Usage

```bash
snell-client -s <server:port> -p <psk> [-l <listen_addr>]
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-s, --server` | Snell server address (host:port) | required |
| `-p, --psk` | Pre-shared key | required |
| `-l, --listen` | Local SOCKS5 listen address | `127.0.0.1:1080` |

### Example

```bash
# Start the client
snell-client -s example.com:6789 -p your_psk_here -l 127.0.0.1:1080

# Use with curl
curl -x socks5h://127.0.0.1:1080 http://example.com
```

### Environment Variables

- `RUST_LOG` - Set log level (`error`, `warn`, `info`, `debug`, `trace`)

```bash
RUST_LOG=info snell-client -s example.com:6789 -p your_psk
```

## License

MIT
