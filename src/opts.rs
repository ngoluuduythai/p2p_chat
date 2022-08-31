use std::str::FromStr;

use clap::Parser;
use libp2p::{core::Multiaddr, PeerId};

#[derive(Debug, Parser)]
#[clap(name = "Chat app p2p")]
pub struct Opts {
  /// The mode (client-listen, client-dial).
  #[clap(long)]
  pub mode: Mode,

  /// Fixed value to generate deterministic peer id.
  #[clap(long)]
  pub secret_key_seed: u8,

  /// The listening address
  #[clap(long)]
  pub relay_address: Multiaddr,

  /// Peer ID of the remote peer to hole punch to.
  #[clap(long)]
  pub remote_peer_id: Option<PeerId>,
}

#[derive(Debug, Parser, PartialEq)]
pub enum Mode {
  Dial,
  Listen,
}

impl FromStr for Mode {
  type Err = String;
  fn from_str(mode: &str) -> Result<Self, Self::Err> {
    match mode {
      "dial" => Ok(Mode::Dial),
      "listen" => Ok(Mode::Listen),
      _ => Err("Expected either 'dial' or 'listen'".to_string()),
    }
  }
}
