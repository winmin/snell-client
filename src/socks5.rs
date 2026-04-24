use anyhow::{bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Minimal SOCKS5 server handshake handler
/// Returns (target_host, target_port) on success

const SOCKS5_VER: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

pub async fn handshake(stream: &mut TcpStream) -> Result<(String, u16)> {
    // Read greeting
    let ver = stream.read_u8().await?;
    if ver != SOCKS5_VER {
        bail!("not socks5");
    }

    let nmethods = stream.read_u8().await?;
    let mut methods = vec![0u8; nmethods as usize];
    stream.read_exact(&mut methods).await?;

    // Reply: no auth required
    stream.write_all(&[SOCKS5_VER, 0x00]).await?;

    // Read connect request
    let ver = stream.read_u8().await?;
    if ver != SOCKS5_VER {
        bail!("not socks5 request");
    }
    let cmd = stream.read_u8().await?;
    if cmd != CMD_CONNECT {
        // Reply with command not supported
        stream
            .write_all(&[SOCKS5_VER, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        bail!("only CONNECT supported, got {}", cmd);
    }
    let _rsv = stream.read_u8().await?;
    let atyp = stream.read_u8().await?;

    let host = match atyp {
        ATYP_IPV4 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
        }
        ATYP_DOMAIN => {
            let len = stream.read_u8().await? as usize;
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await?;
            String::from_utf8(domain)?
        }
        ATYP_IPV6 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            let segments: Vec<String> = ip
                .chunks(2)
                .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                .collect();
            segments.join(":")
        }
        _ => bail!("unknown atyp: {}", atyp),
    };

    let port = stream.read_u16().await?;

    // Reply success
    stream
        .write_all(&[SOCKS5_VER, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    Ok((host, port))
}
