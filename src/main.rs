extern crate core;

mod ecies;
mod message;
mod node;
mod session;

use crate::ecies::ECIES_OVERHEAD;
use crate::node::Address;
use clap::Parser;
use rlp::Encodable;
use secp256k1::rand::rngs::OsRng;
use secp256k1::SecretKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    let secret_key = SecretKey::new(&mut rng);

    let node = args.node;
    let mut conn = TcpStream::connect((node.host, node.port)).await?;

    let _session = session::handshake(conn, &node.public_key, &secret_key).await?;

    Ok(())
}
