extern crate core;

mod ecies;
mod message;
mod node;
mod session;

use crate::ecies::ECIES_OVERHEAD;
use crate::node::Address;
use clap::Parser;
use rlp::Encodable;
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

    let node = args.node;
    let mut conn = TcpStream::connect((node.host, node.port)).await?;

    let mut auth_message = message::AuthMsgV4::default().rlp_bytes().to_vec();
    // append some zeros to make message distinguishable from non EIP-8 (required by eth)
    auth_message.extend_from_slice(&[0u8; 150]);
    let auth_message_size: usize = auth_message.len() + ECIES_OVERHEAD;

    let auth_encrypted = ecies::encrypt(
        auth_message.as_ref(),
        &node.public_key,
        &[],
        &(auth_message_size as u16).to_be_bytes(),
    )?;

    conn.write_u16(auth_message_size as u16).await?;
    conn.write_all(&auth_encrypted).await?;
    conn.flush().await?;
    let res = conn.read_u16().await?;
    println!("Got something: {}", res);

    Ok(())
}
