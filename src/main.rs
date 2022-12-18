extern crate core;

mod ecies;
mod message;
mod node;
mod session;

use crate::node::Address;
use clap::Parser;
use rlp::Encodable;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use url::Url;

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

    let node = args.node;
    let mut conn = TcpStream::connect((node.host, node.port)).await?;

    let payload = ecies::encrypt(
        message::AuthMsgV4::default().rlp_bytes().as_ref(),
        &node.public_key,
        &[0u8; 0],
    )
    .await?;

    conn.write_u16(payload.len() as u16).await?;
    conn.write_all(&payload).await?;
    conn.flush().await?;
    let res = conn.read_u16().await?;
    println!("Got something: {}", res);

    Ok(())
}
