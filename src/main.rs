mod behaviour;
mod event;
mod helper;
mod opts;
mod quic_transport;

use std::net::{Ipv4Addr, SocketAddr, IpAddr};

use anyhow::Result;
use clap::Parser;
use futures::stream::StreamExt;
use futures::{executor::block_on, FutureExt};
use libp2p::core::transport::Boxed;
use libp2p::gossipsub::{self, MessageAuthenticity, ValidationMode};
use libp2p::identify::IdentifyEvent;
use libp2p::kad::store::MemoryStore;
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
use libp2p::{autonat, websocket, dns};
use libp2p::kad;
use opts::{Mode, Opts};
use tracing::info;
use std::str::FromStr;
use std::task::Poll;
use std::time::Duration;

pub const BOOTSTRAP_ADDRESS: &str = "/ip4/3.19.56.240/tcp";
pub const BOOTNODES: &[&str] = &[
  "12D3KooWERHN2kX14rZBbCkKnLKdDzbQfFjA8NUTvHANSmsqbacA",
  "12D3KooWDfVV2caaXhXPsZti1wyZPtBj7kckpQ62oSCS3vxJuzyY",
  "12D3KooWMDoD3xyLF7g4N3a2krrBhW4gBuJ9TZaJ2vUVA5rmfFXt",
  "12D3KooWACdDu7PiwBBukn58ZSjmMKucbB1KvuYPGStzihqSkJVs",
];
const BOOTSTRAP_INTERVAL: Duration = Duration::from_secs(5 * 60);
pub const PORTS: &[u16] = &[4003, 4043, 4344, 4443];

use futures_timer::Delay;
use libp2p::kad::{GetClosestPeersError, Kademlia, KademliaConfig, KademliaEvent, QueryResult};

use crate::quic_transport::{Config, socketaddr_to_multiaddr, QuicTransport};

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
  let transport = 
  // OrTransport::new(
  //   relay_transport,
  //   block_on(DnsConfig::system(TokioTcpTransport::new(
  //     GenTcpConfig::default().port_reuse(true),
  //   )))
  //   .unwrap(),
  // )
  // OrTransport::new(
  //   relay_transport,
  //   block_on(DnsConfig::system(QuicTransport::new(Config::new(&local_key).unwrap())))
  //   .unwrap(),
  // )
  QuicTransport::new(Config::new(&local_key).unwrap())
  // .upgrade(upgrade::Version::V1)
  // .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
  // .multiplex(libp2p::yamux::YamuxConfig::default())
  .boxed();
  // Create a Gossipsub topic
  let topic = gossipsub::IdentTopic::new("chat");

  let mut swarm = {
    // Set mDNS
    let mdns = TokioMdns::new(MdnsConfig::default()).await?;

    let mut cfg = KademliaConfig::default();
    cfg.set_query_timeout(std::time::Duration::from_secs(5 * 60));

    let store = MemoryStore::new(local_peer_id);
    //let kademlia = Kademlia::with_config(local_peer_id, store, cfg);

    let mut kademlia_config = KademliaConfig::default();
    // Instantly remove records and provider records.
    //
    // TODO: Replace hack with option to disable both.
    kademlia_config.set_record_ttl(Some(Duration::from_secs(0)));
    kademlia_config.set_provider_record_ttl(Some(Duration::from_secs(0)));
    let mut kademlia = Kademlia::with_config(local_peer_id, store, kademlia_config);

    //let bootaddr = Multiaddr::from_str("/dnsaddr/bootstrap.libp2p.io").unwrap();
    //ip4/192.168.2.33/tcp/4001


    for (idx, peer) in BOOTNODES.iter().enumerate() {
      kademlia.add_address(
        &PeerId::from_str(peer)?,
        format!("{BOOTSTRAP_ADDRESS}/{}", PORTS[idx]).parse::<Multiaddr>()?,
      );
    }
    // Not find another peer when don't have boostrap  
    let _ = kademlia.bootstrap().unwrap();
    println!("Boostrap: {local_peer_id} success to DHT with qeury id");

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

    let auto_nat = autonat::Behaviour::new(local_peer_id, Default::default());

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
      kademlia,
      autonat: auto_nat,
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
        .with(Protocol::Udp(0))
        .with(Protocol::Quic),
    )?;

// swarm.listen_on(
//   Multiaddr::empty()
//     .with("0.0.0.0".parse::<Ipv4Addr>().unwrap().into())
//     .with(Protocol::Tcp(0)),
// )?;

let dial_addr =
format!("{}/4003/p2p/{}", BOOTSTRAP_ADDRESS, BOOTNODES[0]).parse::<Multiaddr>()?;
info!("Dial addr: {dial_addr}");
swarm.dial(dial_addr.clone())?;

  block_on(async {
    let mut delay = futures_timer::Delay::new(std::time::Duration::from_secs(1)).fuse();
    loop {
      futures::select! {
          event = swarm.next() => {
              match event.unwrap() {
                  SwarmEvent::NewListenAddr { address, .. } => {
                      println!("NewListenAddr Listening on {:?}", address);
                  }
                  event => {
                    //panic!("{:?}", event)
                  },
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
  //swarm.dial(opts.relay_address.clone()).unwrap();

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
        // SwarmEvent::Behaviour(Event::Mdns(event)) => match event {
        //   MdnsEvent::Discovered(list) => {
        //     for (peer, _) in list {
        //       println!("PEER_1: {:?}", peer);
        //       swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
        //     }
        //   }
        //   MdnsEvent::Expired(list) => {
        //     for (peer, _) in list {
        //       if !swarm.behaviour().mdns.has_node(&peer) {
        //         swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer);
        //       }
        //     }
        //   }
        // },
        event => println!("event: {:?}", event),
      }

      if learned_observed_addr && told_relay_observed_addr {
        break;
      }
    }
  });

  // match opts.mode {
  //   Mode::Dial => {
  //     swarm
  //       .dial(
  //         opts
  //           .relay_address
  //           .with(Protocol::P2pCircuit)
  //           .with(Protocol::P2p(opts.remote_peer_id.unwrap().into())),
  //       )
  //       .unwrap();
  //   }
  //   Mode::Listen => {
  //     swarm
  //       .listen_on(opts.relay_address.with(Protocol::P2pCircuit))
  //       .unwrap();
  //   }
  // }

  let mut stdin = tokio::io::BufReader::new(tokio::io::stdin()).lines();
  //let mut bootstrap_timer = Delay::new(BOOTSTRAP_INTERVAL);
  //let _ = swarm.behaviour_mut().kademlia.bootstrap();

  //   block_on(async {
  //     loop {

  //         //if let Poll::Ready(()) = futures::poll!(&mut bootstrap_timer) {
  //            // bootstrap_timer.reset(BOOTSTRAP_INTERVAL);
  //             let _ = swarm
  //                 .behaviour_mut()
  //                 .kademlia
  //                 .bootstrap();
  //        // }

  //         match swarm.next().await.expect("Swarm not to terminate.") {
  //             SwarmEvent::Behaviour(Event::Identify(e)) => {
  //               println!("Identify {:?}", e);

  //                 if let IdentifyEvent::Received {
  //                     peer_id,
  //                     info:
  //                         IdentifyInfo {
  //                             listen_addrs,
  //                             protocols,
  //                             ..
  //                         },
  //                 } = e
  //                 {
  //                     if protocols
  //                         .iter()
  //                         .any(|p| p.as_bytes() == kad::protocol::DEFAULT_PROTO_NAME)
  //                     {
  //                         for addr in listen_addrs {
  //                           println!("Update local DHT {:?}", addr);

  //                             swarm
  //                                 .behaviour_mut()
  //                                 .kademlia
  //                                 .add_address(&peer_id, addr.clone());

  //                                 //swarm.dial("/ip6/::1/tcp/12345".parse::<Multiaddr>().unwrap());
  //                                 swarm.dial(addr).unwrap();
  //                         }
  //                     }
  //                 }
  //             }
  //             SwarmEvent::Behaviour(Event::Ping(e)) => {
  //               println!("Ping {:?}", e);
  //             }
  //             SwarmEvent::Behaviour(Event::Kademlia(e)) => {
  //               println!("Kademlia {:?}", e);
  //             }
  //             SwarmEvent::Behaviour(Event::Relay(e)) => {
  //               println!("Relay {:?}", e);
  //             }
  //             SwarmEvent::Behaviour(Event::AutoNat(e)) => {
  //               println!("AutoNat {:?}", e);

  //             }
  //             SwarmEvent::Behaviour(Event::Gossipsub(GossipsubEvent::Message { message, .. })) => {
  //               println!(
  //                 "Gossipsub Received: '{:?}' from {:?}",
  //                 String::from_utf8_lossy(&message.data),
  //                 message.source
  //               );
  //             }
  //             SwarmEvent::Behaviour(Event::Mdns(event)) => {
  //               println!("Mdns {event:?}");
  //             }
  //             SwarmEvent::NewListenAddr { address, .. } => {
  //                 println!("NewListenAddr Listening on {:?}", address);
  //             }
  //             SwarmEvent::ConnectionEstablished {
  //                 peer_id, endpoint, ..
  //             } => {
  //                 println!("ConnectionEstablished {:?} via {:?}", peer_id, endpoint);
  //             }
  //             SwarmEvent::OutgoingConnectionError { peer_id, error } => {
  //                 println!("OutgoingConnectionError to {:?}: {:?}", peer_id, error);
  //             }
  //             e => {
  //                 if let SwarmEvent::NewListenAddr { address, .. } = &e {
  //                     println!("NewListenAddr Listening on {:?}", address);
  //                 }

  //             }
  //         }
  //     }
  // });

  //println!("Searching for the closest peers to {:?}", local_peer_id);
  //swarm.behaviour_mut().kademlia.get_closest_peers(PeerId::from_str("QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN").unwrap());

  // Kick it off!
  // block_on(async {
  //     loop {
  //         let event = swarm.select_next_some().await;

  //         if let SwarmEvent::Behaviour(Event::Kademlia(KademliaEvent::OutboundQueryCompleted {
  //           result: QueryResult::GetClosestPeers(result),
  //           ..
  //         })) = event
  //         {
  //             match result {
  //                 Ok(ok) => {
  //                     if !ok.peers.is_empty() {
  //                         println!("Query finished with closest peers: {:#?}", ok.peers)
  //                     } else {
  //                         // The example is considered failed as there
  //                         // should always be at least 1 reachable peer.
  //                         println!("Query finished with no closest peers.")
  //                     }
  //                 }
  //                 Err(GetClosestPeersError::Timeout { peers, .. }) => {
  //                     if !peers.is_empty() {
  //                         println!("Query timed out with closest peers: {:#?}", peers)
  //                     } else {
  //                         // The example is considered failed as there
  //                         // should always be at least 1 reachable peer.
  //                         println!("Query timed out with no closest peers.");
  //                     }
  //                 }
  //             };

  //             break;
  //         }
  //     }
  // });

  println!("stdin===============");

  loop {
    tokio::select! {

      line = stdin.next_line() => {
        let line = line?.expect("stdin closed");
        if let Err(e) = swarm
          .behaviour_mut()
          .gossipsub
          .publish(topic.clone(), line.as_bytes()) {
            println!("gossipsub {e:?}");
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
          SwarmEvent::Behaviour(Event::Identify(e)) => {
            println!("Identify {:?}", e);

              if let IdentifyEvent::Received {
                  peer_id,
                  info:
                      IdentifyInfo {
                          listen_addrs,
                          protocols,
                          ..
                      },
              } = e
              {
                  if protocols
                      .iter()
                      .any(|p| p.as_bytes() == kad::protocol::DEFAULT_PROTO_NAME)
                  {
                      for addr in listen_addrs {
                        println!("Update local DHT {:?}", addr);

                          swarm
                              .behaviour_mut()
                              .kademlia
                              .add_address(&peer_id, addr.clone());
                              //swarm.behaviour_mut().gossipsub.add_explicit_peer();
                              //swarm.dial("/ip6/::1/tcp/12345".parse::<Multiaddr>().unwrap());
                              //swarm.dial(addr).unwrap();
                      }
                  }
              }
          }
        //  SwarmEvent::Behaviour(Event::Mdns(event)) => match event {
        //   MdnsEvent::Discovered(list) => {
        //     for (peer, _) in list {
        //       println!("PEER_2: {:?}", peer);
        //       swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
        //     }
        //   }
        //   MdnsEvent::Expired(list) => {
        //     for (peer, _) in list {
        //       if !swarm.behaviour().mdns.has_node(&peer) {
        //         swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer);
        //       }
        //     }
        //   }
        // }

          SwarmEvent::Behaviour(Event::Kademlia(event)) => {
            println!("Kademlia {event:?}");
          }
          SwarmEvent::NewListenAddr { address, .. } => {
              println!("NewListenAddr Listening on {:?}", address);
          }
          SwarmEvent::Behaviour(Event::Relay(client::Event::ReservationReqAccepted {
              ..
          })) => {
              assert!(opts.mode == Mode::Listen);
              println!("Relay accepted our reservation request.");
          }
          SwarmEvent::Behaviour(Event::Relay(event)) => {
              println!("Relay {:?}", event)
          }
          SwarmEvent::Behaviour(Event::Dcutr(event)) => {
              println!("Dcutr {:?}", event)
          }
          SwarmEvent::Behaviour(Event::Ping(_)) => {}
          SwarmEvent::ConnectionEstablished {
              peer_id, endpoint, ..
          } => {
            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
              println!("Established connection to {:?} via {:?}", peer_id, endpoint);
          }
          SwarmEvent::OutgoingConnectionError { peer_id, error } => {
            println!("Outgoing connection error to {peer_id:?}: {error:?}");
        }
        event => println!("Other: {event:?}")
          // _ => {}
        }
      }


    }
  }
}
