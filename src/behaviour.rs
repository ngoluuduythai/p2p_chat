use crate::event::Event;
use libp2p::dcutr;
use libp2p::gossipsub::Gossipsub;
use libp2p::ping::Ping;
use libp2p::{identify::Identify, relay::v2::client::Client, NetworkBehaviour};

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "Event", event_process = false)]
pub struct Behaviour {
  pub relay_client: Client,
  pub ping: Ping,
  pub identify: Identify,
  pub dcutr: dcutr::behaviour::Behaviour,
  pub gossipsub: Gossipsub,
}
