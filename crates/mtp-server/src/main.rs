use clap::Parser;
use mtp_server::{Config, Out, Server};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = Config::parse();
    let server = Server::start(cfg, Out::stdout()).await?;
    server.run_until(tokio::signal::ctrl_c()).await;
    Ok(())
}
