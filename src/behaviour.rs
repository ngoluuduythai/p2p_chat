use crate::event::Event;
use libp2p::dcutr;
use libp2p::gossipsub::Gossipsub;
use libp2p::kad::store::MemoryStore;
use libp2p::kad::Kademlia;
use libp2p::mdns::TokioMdns;
use libp2p::ping::Ping;
use libp2p::{identify::Identify, relay::v2::client::Client, NetworkBehaviour};
use libp2p::autonat;

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "Event", event_process = true)]
pub struct Behaviour {
  pub relay_client: Client,
  pub ping: Ping,
  pub identify: Identify,
  pub dcutr: dcutr::behaviour::Behaviour,
  pub gossipsub: Gossipsub,
  pub mdns: TokioMdns,
  pub kademlia: Kademlia<MemoryStore>,
  pub autonat: autonat::Behaviour,
}
