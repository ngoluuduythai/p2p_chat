mod behaviour;
mod event;
mod helper;
mod opts;

use std::net::Ipv4Addr;

use anyhow::Result;
use clap::Parser;
use futures::stream::StreamExt;
use futures::{executor::block_on, FutureExt};
use libp2p::gossipsub::{self, MessageAuthenticity, ValidationMode};
use libp2p::identify::IdentifyEvent;
use libp2p::kad::store::MemoryStore;
use libp2p::kad::{Kademlia, KademliaConfig};
use libp2p::mdns::{MdnsConfig, MdnsEvent, TokioMdns};
use libp2p::relay::v2::client;
use libp2p::{
  core::{transport::OrTransport, upgrade},
  dcutr,
  dns::DnsConfig,
  gossipsub::GossipsubEvent,
  identify::{Identify, IdentifyConfig, IdentifyInfo},
  multiaddr::Protocol,
  noise,
  ping::{Ping, PingConfig},
  relay::v2::client::Client,
  swarm::{SwarmBuilder, SwarmEvent},
  tcp::{GenTcpConfig, TokioTcpTransport},
  Multiaddr, PeerId, Transport,
};
use rand::Rng;
use tokio::io::AsyncBufReadExt;

use behaviour::Behaviour;
use event::Event;
use helper::generate_ed25519;
use opts::{Mode, Opts};

#[tokio::main]
async fn main() -> Result<()> {
  let opts = Opts::parse();
  println!("{opts:?}");

  let mut rng = rand::thread_rng();
  let random_seed: u8 = rng.gen();
  let local_key = generate_ed25519(random_seed);
  let local_peer_id = PeerId::from(local_key.public());
  println!("Local peer id: {:?}", local_peer_id);

  // Create a keypair for authenticated encryption of the transport.
  let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
    .into_authentic(&local_key)
    .expect("Signing libp2p-noise static DH keypair failed.");

  let (relay_transport, client) = Client::new_transport_and_behaviour(local_peer_id);

  // Create a tokio-based TCP transport use noise for authenticated
  // encryption and Mplex for multiplexing of substreams on a TCP stream.
  let transport = OrTransport::new(
    relay_transport,
    block_on(DnsConfig::system(TokioTcpTransport::new(
      GenTcpConfig::default().port_reuse(true),
    )))
    .unwrap(),
  )
  .upgrade(upgrade::Version::V1)
  .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
  .multiplex(libp2p::yamux::YamuxConfig::default())
  .boxed();

  // Create a Gossipsub topic
  let topic = gossipsub::IdentTopic::new("chat");

  let mut swarm = {
    // Set mDNS
    let mdns = TokioMdns::new(MdnsConfig::default()).await?;

    // let mut cfg = KademliaConfig::default();
    // cfg.set_query_timeout(std::time::Duration::from_secs(5 * 60));

    // let store = MemoryStore::new(local_peer_id);
    // let kademlia = Kademlia::with_config(local_peer_id, store, cfg);

    // Set a custom gossipsub
    let gossipsub_config = gossipsub::GossipsubConfigBuilder::default()
      .heartbeat_interval(std::time::Duration::from_secs(10)) // This is set to aid debugging by not cluttering the log space
      .validation_mode(ValidationMode::Strict) // This sets the kind of message validation. The default is Strict (enforce message signing)
      .build()
      .expect("Valid config");

    // Build a gossipsub network behaviour
    let mut gossipsub: gossipsub::Gossipsub = gossipsub::Gossipsub::new(
      MessageAuthenticity::Signed(local_key.clone()),
      gossipsub_config,
    )
    .expect("Correct configuration");

    // Subscribes to our topic
    gossipsub.subscribe(&topic).unwrap();

    let behaviour = Behaviour {
      relay_client: client,
      ping: Ping::new(PingConfig::new()),
      identify: Identify::new(IdentifyConfig::new(
        "/TODO/0.0.1".to_string(),
        local_key.public(),
      )),
      dcutr: dcutr::behaviour::Behaviour::new(),
      gossipsub,
      mdns,
    };

    // build the swarm
    SwarmBuilder::new(transport, behaviour, local_peer_id)
      .executor(Box::new(|fut| {
        tokio::spawn(fut);
      }))
      .build()
  };

  swarm
    .listen_on(
      Multiaddr::empty()
        .with("0.0.0.0".parse::<Ipv4Addr>().unwrap().into())
        .with(Protocol::Tcp(0)),
    )
    .unwrap();

  block_on(async {
    let mut delay = futures_timer::Delay::new(std::time::Duration::from_secs(1)).fuse();
    loop {
      futures::select! {
          event = swarm.next() => {
              match event.unwrap() {
                  SwarmEvent::NewListenAddr { address, .. } => {
                      println!("Listening on {:?}", address);
                  }
                  event => panic!("{:?}", event),
              }
          }
          _ = delay => {
              // Likely listening on all interfaces now, thus continuing by breaking the loop.
              break;
          }
      }
    }
  });

  // Connect to the relay server. Not for the reservation or relayed connection, but to (a) learn
  // our local public address and (b) enable a freshly started relay to learn its public address.
  swarm.dial(opts.relay_address.clone()).unwrap();
  block_on(async {
    let mut learned_observed_addr = false;
    let mut told_relay_observed_addr = false;

    loop {
      match swarm.next().await.unwrap() {
        SwarmEvent::NewListenAddr { .. } => {}
        SwarmEvent::Dialing { .. } => {}
        SwarmEvent::ConnectionEstablished { .. } => {}
        SwarmEvent::Behaviour(Event::Ping(_)) => {}
        SwarmEvent::Behaviour(Event::Identify(IdentifyEvent::Sent { .. })) => {
          println!("Told relay its public address.");
          told_relay_observed_addr = true;
        }
        SwarmEvent::Behaviour(Event::Identify(IdentifyEvent::Received {
          info: IdentifyInfo { observed_addr, .. },
          ..
        })) => {
          println!("Relay told us our public address: {:?}", observed_addr);
          learned_observed_addr = true;
        }
        SwarmEvent::Behaviour(Event::Mdns(event)) => match event {
          MdnsEvent::Discovered(list) => {
            for (peer, _) in list {
              swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
            }
          }
          MdnsEvent::Expired(list) => {
            for (peer, _) in list {
              if !swarm.behaviour().mdns.has_node(&peer) {
                swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer);
              }
            }
          }
        },
        event => println!("{:?}", event),
      }

      if learned_observed_addr && told_relay_observed_addr {
        break;
      }
    }
  });

  match opts.mode {
    Mode::Dial => {
      swarm
        .dial(
          opts
            .relay_address
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(opts.remote_peer_id.unwrap().into())),
        )
        .unwrap();
    }
    Mode::Listen => {
      swarm
        .listen_on(opts.relay_address.with(Protocol::P2pCircuit))
        .unwrap();
    }
  }

  let mut stdin = tokio::io::BufReader::new(tokio::io::stdin()).lines();

  loop {
    tokio::select! {
      line = stdin.next_line() => {
        let line = line?.expect("stdin closed");
        if let Err(e) = swarm
          .behaviour_mut()
          .gossipsub
          .publish(topic.clone(), line.as_bytes()) {
            println!("{e:?}");
        }
      }
      event = swarm.select_next_some() => {
        match event {
          SwarmEvent::Behaviour(Event::Gossipsub(GossipsubEvent::Message { message, .. })) => {
            println!(
              "Received: '{:?}' from {:?}",
              String::from_utf8_lossy(&message.data),
              message.source
            );
          }
          SwarmEvent::Behaviour(Event::Mdns(event)) => {
            println!("{event:?}");
          }
          // SwarmEvent::Behaviour(Event::Kademlia(event)) => {
          //   println!("{event:?}");
          // }
          SwarmEvent::NewListenAddr { address, .. } => {
              println!("Listening on {:?}", address);
          }
          SwarmEvent::Behaviour(Event::Relay(client::Event::ReservationReqAccepted {
              ..
          })) => {
              assert!(opts.mode == Mode::Listen);
              println!("Relay accepted our reservation request.");
          }
          SwarmEvent::Behaviour(Event::Relay(event)) => {
              println!("{:?}", event)
          }
          SwarmEvent::Behaviour(Event::Dcutr(event)) => {
              println!("{:?}", event)
          }
          SwarmEvent::Behaviour(Event::Identify(event)) => {
              println!("{:?}", event)
          }
          SwarmEvent::Behaviour(Event::Ping(_)) => {}
          SwarmEvent::ConnectionEstablished {
              peer_id, endpoint, ..
          } => {
              println!("Established connection to {:?} via {:?}", peer_id, endpoint);
          }
          SwarmEvent::OutgoingConnectionError { peer_id, error } => {
              println!("Outgoing connection error to {:?}: {:?}", peer_id, error);
          }
          _ => {}
        }
      }
    }
  }
}
