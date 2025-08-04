//! P2P network implementation for blockchain nodes

use crate::block::Block;
use crate::crypto::Hash;
use crate::error::{BlockchainError, Result};
use crate::transaction::Transaction;
use futures::prelude::*;
use libp2p::{
    core::upgrade,
    floodsub::{Floodsub, FloodsubEvent, Topic},
    identity,
    mdns::{Mdns, MdnsEvent},
    mplex,
    noise::{Keypair, NoiseConfig, X25519Spec},
    swarm::{NetworkBehaviour, Swarm, SwarmBuilder, SwarmEvent},
    tcp::TokioTcpConfig,
    Multiaddr, NetworkBehaviour, PeerId, Transport,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Network message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    /// Request for blockchain info
    GetBlockchainInfo,
    /// Response with blockchain info
    BlockchainInfo {
        height: u64,
        best_hash: Hash,
        difficulty: u32,
    },
    /// Request for blocks starting from a specific height
    GetBlocks { start_height: u64, count: u32 },
    /// Response with blocks
    Blocks(Vec<Block>),
    /// Request for a specific block by hash
    GetBlock(Hash),
    /// Response with a block
    Block(Block),
    /// New block announcement
    NewBlock(Block),
    /// New transaction announcement
    NewTransaction(Transaction),
    /// Request for mempool transactions
    GetMempool,
    /// Response with mempool transactions
    Mempool(Vec<Transaction>),
    /// Ping message
    Ping,
    /// Pong response
    Pong,
    /// Peer list request
    GetPeers,
    /// Peer list response
    Peers(Vec<PeerId>),
}

/// Network event types
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// New peer connected
    PeerConnected(PeerId),
    /// Peer disconnected
    PeerDisconnected(PeerId),
    /// Received a message from a peer
    MessageReceived {
        peer_id: PeerId,
        message: NetworkMessage,
    },
    /// New block received
    NewBlock(Block),
    /// New transaction received
    NewTransaction(Transaction),
    /// Blockchain sync request
    SyncRequest {
        peer_id: PeerId,
        start_height: u64,
    },
}

/// Network behavior combining Floodsub and mDNS
#[derive(NetworkBehaviour)]
#[behaviour(out_event = "NetworkBehaviourEvent")]
struct BlockchainBehaviour {
    floodsub: Floodsub,
    mdns: Mdns,
}

#[derive(Debug)]
enum NetworkBehaviourEvent {
    Floodsub(FloodsubEvent),
    Mdns(MdnsEvent),
}

impl From<FloodsubEvent> for NetworkBehaviourEvent {
    fn from(event: FloodsubEvent) -> Self {
        NetworkBehaviourEvent::Floodsub(event)
    }
}

impl From<MdnsEvent> for NetworkBehaviourEvent {
    fn from(event: MdnsEvent) -> Self {
        NetworkBehaviourEvent::Mdns(event)
    }
}

/// Network configuration
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Local peer ID
    pub peer_id: PeerId,
    /// Listen addresses
    pub listen_addresses: Vec<Multiaddr>,
    /// Bootstrap peers
    pub bootstrap_peers: Vec<Multiaddr>,
    /// Maximum number of peers
    pub max_peers: usize,
    /// Network protocol version
    pub protocol_version: String,
    /// Chain ID
    pub chain_id: String,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        let local_key = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(local_key.public());
        
        Self {
            peer_id,
            listen_addresses: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
            bootstrap_peers: Vec::new(),
            max_peers: 50,
            protocol_version: "rust-blockchain/1.0".to_string(),
            chain_id: "main".to_string(),
        }
    }
}

/// Peer information
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Peer ID
    pub peer_id: PeerId,
    /// Connected addresses
    pub addresses: Vec<Multiaddr>,
    /// Connection timestamp
    pub connected_at: u64,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Protocol version
    pub protocol_version: Option<String>,
    /// Best block height
    pub best_height: Option<u64>,
    /// Best block hash
    pub best_hash: Option<Hash>,
}

impl PeerInfo {
    fn new(peer_id: PeerId) -> Self {
        let now = crate::utils::current_timestamp();
        Self {
            peer_id,
            addresses: Vec::new(),
            connected_at: now,
            last_seen: now,
            protocol_version: None,
            best_height: None,
            best_hash: None,
        }
    }
    
    fn update_last_seen(&mut self) {
        self.last_seen = crate::utils::current_timestamp();
    }
}

/// Network statistics
#[derive(Debug, Clone)]
pub struct NetworkStats {
    /// Number of connected peers
    pub connected_peers: usize,
    /// Total messages sent
    pub messages_sent: u64,
    /// Total messages received
    pub messages_received: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Network uptime in seconds
    pub uptime: u64,
}

/// P2P Network manager
pub struct Network {
    /// Network configuration
    config: NetworkConfig,
    /// Swarm for managing connections
    swarm: Swarm<BlockchainBehaviour>,
    /// Connected peers
    peers: Arc<RwLock<HashMap<PeerId, PeerInfo>>>,
    /// Network statistics
    stats: Arc<RwLock<NetworkStats>>,
    /// Event sender
    event_sender: mpsc::UnboundedSender<NetworkEvent>,
    /// Start time
    start_time: u64,
    /// Topics for pub/sub
    topics: HashMap<String, Topic>,
}

impl Network {
    /// Create a new network instance
    pub async fn new(
        config: NetworkConfig,
        event_sender: mpsc::UnboundedSender<NetworkEvent>,
    ) -> Result<Self> {
        // Generate a random PeerId
        let local_key = identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());
        
        // Create a keypair for authenticated encryption
        let noise_keys = Keypair::<X25519Spec>::new()
            .into_authentic(&local_key)
            .map_err(|e| BlockchainError::NetworkError(format!("Failed to create noise keys: {}", e)))?;
        
        // Create the transport
        let transport = TokioTcpConfig::new()
            .upgrade(upgrade::Version::V1)
            .authenticate(NoiseConfig::xx(noise_keys).into_authenticated())
            .multiplex(mplex::MplexConfig::new())
            .boxed();
        
        // Create network behaviour
        let mut behaviour = BlockchainBehaviour {
            floodsub: Floodsub::new(local_peer_id),
            mdns: Mdns::new(Default::default())
                .await
                .map_err(|e| BlockchainError::NetworkError(format!("Failed to create mDNS: {}", e)))?,
        };
        
        // Subscribe to topics
        let mut topics = HashMap::new();
        let topic_names = vec!["blocks", "transactions", "sync", "general"];
        
        for topic_name in topic_names {
            let topic = Topic::new(format!("{}-{}", config.chain_id, topic_name));
            behaviour.floodsub.subscribe(topic.clone());
            topics.insert(topic_name.to_string(), topic);
        }
        
        // Create swarm
        let swarm = SwarmBuilder::new(transport, behaviour, local_peer_id)
            .executor(Box::new(|fut| {
                tokio::spawn(fut);
            }))
            .build();
        
        let stats = NetworkStats {
            connected_peers: 0,
            messages_sent: 0,
            messages_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            uptime: 0,
        };
        
        Ok(Self {
            config,
            swarm,
            peers: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(stats)),
            event_sender,
            start_time: crate::utils::current_timestamp(),
            topics,
        })
    }
    
    /// Start the network
    pub async fn start(&mut self) -> Result<()> {
        // Listen on configured addresses
        for addr in &self.config.listen_addresses {
            self.swarm
                .listen_on(addr.clone())
                .map_err(|e| BlockchainError::NetworkError(format!("Failed to listen on {}: {}", addr, e)))?;
        }
        
        // Connect to bootstrap peers
        for peer_addr in &self.config.bootstrap_peers {
            if let Err(e) = self.swarm.dial(peer_addr.clone()) {
                warn!("Failed to dial bootstrap peer {}: {}", peer_addr, e);
            }
        }
        
        info!("Network started with peer ID: {}", self.swarm.local_peer_id());
        Ok(())
    }
    
    /// Run the network event loop
    pub async fn run(&mut self) -> Result<()> {
        loop {
            match self.swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => {
                    info!("Listening on {}", address);
                }
                SwarmEvent::Behaviour(NetworkBehaviourEvent::Floodsub(FloodsubEvent::Message(message))) => {
                    self.handle_floodsub_message(message).await;
                }
                SwarmEvent::Behaviour(NetworkBehaviourEvent::Mdns(MdnsEvent::Discovered(list))) => {
                    for (peer_id, multiaddr) in list {
                        debug!("Discovered peer {} at {}", peer_id, multiaddr);
                        self.swarm.behaviour_mut().floodsub.add_node_to_partial_view(peer_id);
                    }
                }
                SwarmEvent::Behaviour(NetworkBehaviourEvent::Mdns(MdnsEvent::Expired(list))) => {
                    for (peer_id, _multiaddr) in list {
                        debug!("Peer {} expired", peer_id);
                        self.swarm.behaviour_mut().floodsub.remove_node_from_partial_view(&peer_id);
                    }
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    self.handle_peer_connected(peer_id).await;
                }
                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    self.handle_peer_disconnected(peer_id).await;
                }
                _ => {}
            }
        }
    }
    
    /// Handle floodsub message
    async fn handle_floodsub_message(&mut self, message: libp2p::floodsub::FloodsubMessage) {
        let peer_id = message.source;
        
        // Update stats
        {
            let mut stats = self.stats.write().unwrap();
            stats.messages_received += 1;
            stats.bytes_received += message.data.len() as u64;
        }
        
        // Update peer last seen
        if let Some(peer_info) = self.peers.write().unwrap().get_mut(&peer_id) {
            peer_info.update_last_seen();
        }
        
        // Deserialize message
        match bincode::deserialize::<NetworkMessage>(&message.data) {
            Ok(network_message) => {
                debug!("Received message from {}: {:?}", peer_id, network_message);
                
                // Send event
                if let Err(e) = self.event_sender.send(NetworkEvent::MessageReceived {
                    peer_id,
                    message: network_message.clone(),
                }) {
                    error!("Failed to send network event: {}", e);
                }
                
                // Handle specific message types
                match network_message {
                    NetworkMessage::NewBlock(block) => {
                        if let Err(e) = self.event_sender.send(NetworkEvent::NewBlock(block)) {
                            error!("Failed to send new block event: {}", e);
                        }
                    }
                    NetworkMessage::NewTransaction(transaction) => {
                        if let Err(e) = self.event_sender.send(NetworkEvent::NewTransaction(transaction)) {
                            error!("Failed to send new transaction event: {}", e);
                        }
                    }
                    NetworkMessage::GetBlocks { start_height, .. } => {
                        if let Err(e) = self.event_sender.send(NetworkEvent::SyncRequest {
                            peer_id,
                            start_height,
                        }) {
                            error!("Failed to send sync request event: {}", e);
                        }
                    }
                    _ => {}
                }
            }
            Err(e) => {
                warn!("Failed to deserialize message from {}: {}", peer_id, e);
            }
        }
    }
    
    /// Handle peer connected
    async fn handle_peer_connected(&mut self, peer_id: PeerId) {
        info!("Peer connected: {}", peer_id);
        
        // Add to peers list
        {
            let mut peers = self.peers.write().unwrap();
            peers.insert(peer_id, PeerInfo::new(peer_id));
        }
        
        // Update stats
        {
            let mut stats = self.stats.write().unwrap();
            stats.connected_peers = self.peers.read().unwrap().len();
        }
        
        // Send event
        if let Err(e) = self.event_sender.send(NetworkEvent::PeerConnected(peer_id)) {
            error!("Failed to send peer connected event: {}", e);
        }
    }
    
    /// Handle peer disconnected
    async fn handle_peer_disconnected(&mut self, peer_id: PeerId) {
        info!("Peer disconnected: {}", peer_id);
        
        // Remove from peers list
        {
            let mut peers = self.peers.write().unwrap();
            peers.remove(&peer_id);
        }
        
        // Update stats
        {
            let mut stats = self.stats.write().unwrap();
            stats.connected_peers = self.peers.read().unwrap().len();
        }
        
        // Send event
        if let Err(e) = self.event_sender.send(NetworkEvent::PeerDisconnected(peer_id)) {
            error!("Failed to send peer disconnected event: {}", e);
        }
    }
    
    /// Broadcast a message to all peers
    pub fn broadcast_message(&mut self, message: NetworkMessage, topic: &str) -> Result<()> {
        let topic = self.topics.get(topic)
            .ok_or_else(|| BlockchainError::NetworkError(format!("Unknown topic: {}", topic)))?;
        
        let data = bincode::serialize(&message)
            .map_err(|e| BlockchainError::SerializationError(e.to_string()))?;
        
        self.swarm.behaviour_mut().floodsub.publish(topic.clone(), data.clone());
        
        // Update stats
        {
            let mut stats = self.stats.write().unwrap();
            stats.messages_sent += 1;
            stats.bytes_sent += data.len() as u64;
        }
        
        debug!("Broadcasted message to topic {}: {:?}", topic, message);
        Ok(())
    }
    
    /// Send a message to a specific peer
    pub fn send_message_to_peer(&mut self, peer_id: PeerId, message: NetworkMessage) -> Result<()> {
        // For now, we'll use broadcast since libp2p floodsub doesn't support direct messaging
        // In a production system, you might want to use a different protocol for direct messaging
        self.broadcast_message(message, "general")
    }
    
    /// Broadcast a new block
    pub fn broadcast_block(&mut self, block: Block) -> Result<()> {
        self.broadcast_message(NetworkMessage::NewBlock(block), "blocks")
    }
    
    /// Broadcast a new transaction
    pub fn broadcast_transaction(&mut self, transaction: Transaction) -> Result<()> {
        self.broadcast_message(NetworkMessage::NewTransaction(transaction), "transactions")
    }
    
    /// Request blockchain info from peers
    pub fn request_blockchain_info(&mut self) -> Result<()> {
        self.broadcast_message(NetworkMessage::GetBlockchainInfo, "sync")
    }
    
    /// Request blocks from a specific height
    pub fn request_blocks(&mut self, start_height: u64, count: u32) -> Result<()> {
        self.broadcast_message(
            NetworkMessage::GetBlocks { start_height, count },
            "sync"
        )
    }
    
    /// Get connected peers
    pub fn get_peers(&self) -> Vec<PeerInfo> {
        self.peers.read().unwrap().values().cloned().collect()
    }
    
    /// Get network statistics
    pub fn get_stats(&self) -> NetworkStats {
        let mut stats = self.stats.read().unwrap().clone();
        stats.uptime = crate::utils::current_timestamp().saturating_sub(self.start_time);
        stats
    }
    
    /// Get local peer ID
    pub fn local_peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }
    
    /// Get listen addresses
    pub fn listen_addresses(&self) -> Vec<Multiaddr> {
        self.swarm.listeners().cloned().collect()
    }
}

/// Network event handler trait
pub trait NetworkEventHandler {
    fn handle_peer_connected(&mut self, peer_id: PeerId);
    fn handle_peer_disconnected(&mut self, peer_id: PeerId);
    fn handle_message_received(&mut self, peer_id: PeerId, message: NetworkMessage);
    fn handle_new_block(&mut self, block: Block);
    fn handle_new_transaction(&mut self, transaction: Transaction);
    fn handle_sync_request(&mut self, peer_id: PeerId, start_height: u64);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[test]
    fn test_network_config_default() {
        let config = NetworkConfig::default();
        assert!(!config.listen_addresses.is_empty());
        assert_eq!(config.max_peers, 50);
        assert_eq!(config.protocol_version, "rust-blockchain/1.0");
        assert_eq!(config.chain_id, "main");
    }

    #[test]
    fn test_peer_info_creation() {
        let peer_id = PeerId::random();
        let peer_info = PeerInfo::new(peer_id);
        
        assert_eq!(peer_info.peer_id, peer_id);
        assert!(peer_info.connected_at > 0);
        assert_eq!(peer_info.connected_at, peer_info.last_seen);
    }

    #[test]
    fn test_network_message_serialization() {
        let message = NetworkMessage::Ping;
        let serialized = bincode::serialize(&message).unwrap();
        let deserialized: NetworkMessage = bincode::deserialize(&serialized).unwrap();
        
        match deserialized {
            NetworkMessage::Ping => {},
            _ => panic!("Unexpected message type"),
        }
    }

    #[tokio::test]
    async fn test_network_creation() {
        let config = NetworkConfig::default();
        let (sender, _receiver) = mpsc::unbounded_channel();
        
        let result = Network::new(config, sender).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_network_stats() {
        let stats = NetworkStats {
            connected_peers: 5,
            messages_sent: 100,
            messages_received: 150,
            bytes_sent: 1024,
            bytes_received: 2048,
            uptime: 3600,
        };
        
        assert_eq!(stats.connected_peers, 5);
        assert_eq!(stats.messages_sent, 100);
        assert_eq!(stats.uptime, 3600);
    }
}