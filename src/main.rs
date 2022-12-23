mod crypto;
mod ecies;
mod message;
mod node;
mod session;

use crate::message::{Capability, Frame, Hello};
use crate::node::Address;
use clap::Parser;
use secp256k1::rand::rngs::OsRng;
use secp256k1::{Secp256k1, SecretKey};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::sleep;

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
    // but for demo purposes its fine to generate new one
    let secret_key = SecretKey::new(&mut rng);

    let node = args.node;
    let conn = TcpStream::connect((node.host, node.port)).await?;

    let mut session = session::handshake(conn, &node.public_key, &secret_key).await?;
    // send hello first
    session
        .write_frame(
            &Hello {
                proto_version: 5,
                client_id: "p2p handshaker 0.1.0".to_string(),
                capabilities: vec![Capability {
                    name: "eth".to_string(),
                    version: 66,
                }],
                listen_port: 0,
                node_id: secret_key
                    .public_key(&Secp256k1::new())
                    .serialize_uncompressed()[1..]
                    .to_vec(),
            }
            .into(),
        )
        .await?;
    // wait for hello from peer
    let hello_frame: Frame<Hello> = session.read_frame().await?;
    println!("Hello from peer: {:?}", hello_frame);
    // from this point session is established
    println!("Giving a chance for peer to process our hello");
    sleep(Duration::from_secs(5)).await;
    println!("Done - bailing out (gracefully)");
    session.shutdown().await?;
    sleep(Duration::from_secs(1)).await;
    Ok(())
}
