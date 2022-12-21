mod crypto;
mod ecies;
mod message;
mod node;
mod session;

use crate::message::{Frame, Hello};
use crate::node::Address;
use clap::Parser;
use secp256k1::rand::rngs::OsRng;
use secp256k1::SecretKey;
use tokio::net::TcpStream;

#[derive(Parser, Debug)]
#[command(about, long_about = None)]
pub struct Args {
    /// URL of eth node
    #[arg(long)]
    node: Address,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let mut rng = OsRng;
    // TODO this should be externally stored key loaded on startup
    // but for demo purposes its fine
    let secret_key = SecretKey::new(&mut rng);

    let node = args.node;
    let conn = TcpStream::connect((node.host, node.port)).await?;

    let mut session = session::handshake(conn, &node.public_key, &secret_key).await?;
    let hello_frame: Frame<Hello> = session.read_message().await?;
    println!("Hello from peer: {:?}", hello_frame);
    Ok(())
}
