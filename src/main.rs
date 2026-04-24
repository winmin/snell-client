mod crypto;
mod protocol;
mod socks5;

use anyhow::Result;
use clap::Parser;
use std::sync::Arc;
use tokio::net::TcpListener;

#[derive(Parser)]
#[command(name = "snell-client", about = "Snell v5 proxy client (SOCKS5 frontend)")]
struct Args {
    /// Snell server address (host:port)
    #[arg(short, long)]
    server: String,

    /// Pre-shared key
    #[arg(short, long)]
    psk: String,

    /// Local SOCKS5 listen address
    #[arg(short, long, default_value = "127.0.0.1:1080")]
    listen: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let psk: Arc<str> = Arc::from(args.psk.as_str());

    let listener = TcpListener::bind(&args.listen).await?;
    tracing::info!("SOCKS5 listening on {}", args.listen);
    tracing::info!("Snell server: {}", args.server);

    loop {
        let (client, addr) = listener.accept().await?;
        let server = args.server.clone();
        let psk = psk.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_client(client, &server, psk).await {
                tracing::debug!("connection from {} error: {}", addr, e);
            }
        });
    }
}

async fn handle_client(
    mut client: tokio::net::TcpStream,
    server: &str,
    psk: std::sync::Arc<str>,
) -> Result<()> {
    let (host, port) = socks5::handshake(&mut client).await?;
    tracing::info!("proxying to {}:{}", host, port);

    let mut session = protocol::SnellSession::connect(server, psk).await?;
    session.send_connect(&host, port).await?;
    protocol::relay_bidirectional(session, client).await?;
    Ok(())
}
