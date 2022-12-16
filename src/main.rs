mod node;

use crate::node::Address;
use clap::Parser;
use url::Url;

#[derive(Parser, Debug)]
#[command(about, long_about = None)]
pub struct Args {
    /// URL of eth node
    #[arg(long)]
    node: Address,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    println!("{:?}", args);
    Ok(())
}
