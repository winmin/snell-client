use anyhow::{bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use crate::crypto::{self, AeadCipher, SALT_LEN, TAG_LEN};

const SNELL_VERSION: u8 = 1;
const CMD_CONNECT: u8 = 1;
const ENC_HEADER_LEN: usize = 7 + TAG_LEN; // 23
const MAX_PAYLOAD: usize = 16384;
const WRITE_BUF_SIZE: usize = ENC_HEADER_LEN + MAX_PAYLOAD + TAG_LEN;

pub struct SnellSession {
    stream: TcpStream,
    enc: AeadCipher,
    psk: std::sync::Arc<str>,
}

#[inline]
fn build_header(payload_len: u16) -> [u8; 7] {
    [4, 0, 0, 0, 0, (payload_len >> 8) as u8, (payload_len & 0xff) as u8]
}

#[inline]
fn parse_header(header: &[u8]) -> (u16, u16) {
    let padding_len = ((header[3] as u16) << 8) | (header[4] as u16);
    let payload_len = ((header[5] as u16) << 8) | (header[6] as u16);
    (padding_len, payload_len)
}

impl SnellSession {
    pub async fn connect(server: &str, psk: std::sync::Arc<str>) -> Result<Self> {
        let stream = TcpStream::connect(server).await?;
        stream.set_nodelay(true)?;

        let client_salt = crypto::generate_salt();
        let mut client_key = crypto::derive_key(&psk, &client_salt)?;
        let enc = AeadCipher::new(&mut client_key);

        let mut session = Self { stream, enc, psk };
        session.stream.write_all(&client_salt).await?;
        Ok(session)
    }

    pub async fn send_connect(&mut self, host: &str, port: u16) -> Result<()> {
        let host_bytes = host.as_bytes();
        if host_bytes.len() > 255 {
            bail!("hostname too long");
        }

        let mut req = Vec::with_capacity(6 + host_bytes.len());
        req.push(SNELL_VERSION);
        req.push(CMD_CONNECT);
        req.push(0);
        req.push(host_bytes.len() as u8);
        req.extend_from_slice(host_bytes);
        req.push((port >> 8) as u8);
        req.push((port & 0xff) as u8);

        let payload_len = req.len() as u16;
        let mut header_buf = build_header(payload_len).to_vec();
        self.enc.encrypt_in_place(&mut header_buf)?;
        self.enc.encrypt_in_place(&mut req)?;

        let mut out = Vec::with_capacity(header_buf.len() + req.len());
        out.extend_from_slice(&header_buf);
        out.extend_from_slice(&req);
        self.stream.write_all(&out).await?;
        self.stream.flush().await?;
        Ok(())
    }

    // relay is handled by relay_bidirectional() below
}

// Better relay with proper cancellation
pub async fn relay_bidirectional(
    session: SnellSession,
    local: TcpStream,
) -> Result<()> {
    let (local_r, local_w) = local.into_split();
    let (snell_r, snell_w) = session.stream.into_split();

    let psk = session.psk;
    let mut upload_handle = tokio::spawn(relay_upload(local_r, snell_w, session.enc));
    let mut download_handle = tokio::spawn(relay_download_with_init(snell_r, local_w, psk));

    // Wait for either to finish, then abort the other
    tokio::select! {
        _ = &mut upload_handle => {
            download_handle.abort();
        }
        _ = &mut download_handle => {
            upload_handle.abort();
        }
    }
    Ok(())
}

/// Read and decrypt one frame.
async fn read_frame(
    reader: &mut OwnedReadHalf,
    dec: &mut AeadCipher,
    header_buf: &mut Vec<u8>,
    payload_buf: &mut Vec<u8>, // reusable buffer to reduce allocations
) -> Result<usize> {
    // Read encrypted header into reusable buffer
    header_buf.resize(ENC_HEADER_LEN, 0);
    reader.read_exact(header_buf).await?;
    dec.decrypt_in_place(header_buf)?;

    let (padding_len, payload_len) = parse_header(header_buf);

    if payload_len == 0 && padding_len == 0 {
        payload_buf.clear();
        return Ok(0);
    }

    let enc_payload_len = payload_len as usize + TAG_LEN;

    if padding_len > 0 {
        let pad_len = padding_len as usize;
        if payload_len == 0 {
            // Skip padding, reuse payload_buf as scratch
            payload_buf.resize(pad_len, 0);
            reader.read_exact(payload_buf).await?;
            payload_buf.clear();
            return Ok(0);
        }
        // Read padding + enc_payload contiguously
        let total = pad_len + enc_payload_len;
        payload_buf.resize(total, 0);
        reader.read_exact(payload_buf).await?;

        // Undo byte interleave swap
        let swap_limit = pad_len.min(enc_payload_len);
        let mut i = 0;
        while i < swap_limit {
            payload_buf.swap(i, pad_len + i);
            i += 2;
        }

        // Move payload portion to front, decrypt in-place
        payload_buf.drain(..pad_len);
        dec.decrypt_in_place(payload_buf)?;
        Ok(payload_buf.len())
    } else {
        if payload_len == 0 {
            payload_buf.clear();
            return Ok(0);
        }
        payload_buf.resize(enc_payload_len, 0);
        reader.read_exact(payload_buf).await?;
        dec.decrypt_in_place(payload_buf)?;
        Ok(payload_buf.len())
    }
}

async fn relay_upload(
    mut local_r: OwnedReadHalf,
    snell_w: OwnedWriteHalf,
    mut enc: AeadCipher,
) {
    let mut writer = BufWriter::with_capacity(WRITE_BUF_SIZE, snell_w);
    let mut read_buf = vec![0u8; MAX_PAYLOAD];
    // Reusable write buffer to avoid per-frame allocation
    let mut write_buf = Vec::with_capacity(ENC_HEADER_LEN + MAX_PAYLOAD + TAG_LEN);

    loop {
        let n = match local_r.read(&mut read_buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };

        // Build encrypted frame into write_buf
        write_buf.clear();
        write_buf.extend_from_slice(&build_header(n as u16));
        // Encrypt header portion in-place (first 7 bytes → 23 bytes)
        if enc.encrypt_in_place(&mut write_buf).is_err() {
            break;
        }

        let header_end = write_buf.len();
        write_buf.extend_from_slice(&read_buf[..n]);
        // Encrypt payload portion (appended bytes)
        let mut payload_part = write_buf.split_off(header_end);
        if enc.encrypt_in_place(&mut payload_part).is_err() {
            break;
        }
        write_buf.extend_from_slice(&payload_part);

        if writer.write_all(&write_buf).await.is_err() {
            break;
        }
        if writer.flush().await.is_err() {
            break;
        }
    }

    // Send zero chunk
    let mut zero = [0u8; 7].to_vec();
    if enc.encrypt_in_place(&mut zero).is_ok() {
        let _ = writer.write_all(&zero).await;
        let _ = writer.flush().await;
    }
}

async fn relay_download_with_init(
    mut snell_r: OwnedReadHalf,
    mut local_w: OwnedWriteHalf,
    psk: std::sync::Arc<str>,
) {
    let mut server_salt = [0u8; SALT_LEN];
    if snell_r.read_exact(&mut server_salt).await.is_err() {
        return;
    }

    let mut server_key = match crypto::derive_key(&psk, &server_salt) {
        Ok(k) => k,
        Err(_) => return,
    };
    let mut dec = AeadCipher::new(&mut server_key);
    let mut header_buf = Vec::with_capacity(ENC_HEADER_LEN);
    let mut payload_buf = Vec::with_capacity(MAX_PAYLOAD + TAG_LEN);

    // Read CONNECT response
    match read_frame(&mut snell_r, &mut dec, &mut header_buf, &mut payload_buf).await {
        Ok(0) => {
            tracing::debug!("empty connect response");
            return;
        }
        Ok(_) => {
            if payload_buf[0] != 0 {
                tracing::debug!("server rejected CONNECT: {}", payload_buf[0]);
                return;
            }
            tracing::info!("tunnel established");
            if payload_buf.len() > 1 {
                if local_w.write_all(&payload_buf[1..]).await.is_err() {
                    return;
                }
            }
        }
        Err(e) => {
            tracing::debug!("connect response error: {}", e);
            return;
        }
    }

    // Relay loop — reuses header_buf and payload_buf across frames
    loop {
        match read_frame(&mut snell_r, &mut dec, &mut header_buf, &mut payload_buf).await {
            Ok(0) => break,
            Ok(_) => {
                if local_w.write_all(&payload_buf).await.is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}
