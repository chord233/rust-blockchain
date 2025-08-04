//! Blockchain node binary
//! 
//! This is the main blockchain node that handles P2P networking,
//! block validation, transaction processing, and consensus.

use anyhow::Result;
use clap::{Arg, Command};
use rust_blockchain::{
    block::Block,
    blockchain::Blockchain,
    consensus::ProofOfWork,
    crypto::Hash,
    error::BlockchainError,
    mempool::Mempool,
    network::{Network, NetworkConfig, NetworkEvent, NetworkMessage},
    storage::Storage,
    transaction::Transaction,
    wallet::WalletManager,
};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use tracing_subscriber;

/// Node configuration
#[derive(Debug, Clone)]
struct NodeConfig {
    /// Data directory
    data_dir: PathBuf,
    /// Network listen address
    listen_addr: String,
    /// Bootstrap peers
    bootstrap_peers: Vec<String>,
    /// Enable mining
    enable_mining: bool,
    /// Mining address
    mining_address: Option<String>,
    /// RPC port
    rpc_port: u16,
    /// Log level
    log_level: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data"),
            listen_addr: "/ip4/0.0.0.0/tcp/8333".to_string(),
            bootstrap_peers: Vec::new(),
            enable_mining: false,
            mining_address: None,
            rpc_port: 8332,
            log_level: "info".to_string(),
        }
    }
}

/// Blockchain node
struct Node {
    /// Node configuration
    config: NodeConfig,
    /// Blockchain instance
    blockchain: Arc<RwLock<Blockchain>>,
    /// Memory pool
    mempool: Arc<Mempool>,
    /// Network instance
    network: Option<Network>,
    /// Consensus engine
    consensus: ProofOfWork,
    /// Wallet manager
    wallet_manager: Arc<RwLock<WalletManager>>,
    /// Network event receiver
    network_event_receiver: Option<mpsc::UnboundedReceiver<NetworkEvent>>,
}

impl Node {
    /// Create a new node
    async fn new(config: NodeConfig) -> Result<Self> {
        // Initialize storage
        let storage_path = config.data_dir.join("blockchain");
        let storage = Storage::new(&storage_path)?;
        
        // Initialize blockchain
        let blockchain = if storage.is_empty()? {
            info!("Creating new blockchain");
            Blockchain::new(storage)?
        } else {
            info!("Loading existing blockchain");
            Blockchain::load(storage)?
        };
        
        // Initialize mempool
        let mempool = Arc::new(Mempool::default());
        
        // Initialize consensus
        let consensus = ProofOfWork::default();
        
        // Initialize wallet manager
        let wallet_path = config.data_dir.join("wallets");
        let wallet_manager = Arc::new(RwLock::new(WalletManager::new(&wallet_path)?));
        
        // Create network event channel
        let (network_event_sender, network_event_receiver) = mpsc::unbounded_channel();
        
        // Initialize network
        let mut network_config = NetworkConfig::default();
        network_config.listen_addresses = vec![config.listen_addr.parse()?];
        network_config.bootstrap_peers = config.bootstrap_peers
            .iter()
            .map(|addr| addr.parse())
            .collect::<Result<Vec<_>, _>>()?;
        
        let network = Network::new(network_config, network_event_sender).await?;
        
        Ok(Self {
            config,
            blockchain: Arc::new(RwLock::new(blockchain)),
            mempool,
            network: Some(network),
            consensus,
            wallet_manager,
            network_event_receiver: Some(network_event_receiver),
        })
    }
    
    /// Start the node
    async fn start(&mut self) -> Result<()> {
        info!("Starting blockchain node");
        
        // Start network
        if let Some(ref mut network) = self.network {
            network.start().await?;
        }
        
        // Start event processing
        let network_event_receiver = self.network_event_receiver.take().unwrap();
        let blockchain = Arc::clone(&self.blockchain);
        let mempool = Arc::clone(&self.mempool);
        let consensus = self.consensus.clone();
        
        tokio::spawn(async move {
            Self::process_network_events(
                network_event_receiver,
                blockchain,
                mempool,
                consensus,
            ).await;
        });
        
        // Start mining if enabled
        if self.config.enable_mining {
            if let Some(ref mining_address) = self.config.mining_address {
                let blockchain = Arc::clone(&self.blockchain);
                let mempool = Arc::clone(&self.mempool);
                let consensus = self.consensus.clone();
                let mining_address = mining_address.clone();
                
                tokio::spawn(async move {
                    Self::mining_loop(blockchain, mempool, consensus, mining_address).await;
                });
            } else {
                warn!("Mining enabled but no mining address specified");
            }
        }
        
        // Start RPC server
        self.start_rpc_server().await?;
        
        // Run network event loop
        if let Some(ref mut network) = self.network {
            network.run().await?;
        }
        
        Ok(())
    }
    
    /// Process network events
    async fn process_network_events(
        mut receiver: mpsc::UnboundedReceiver<NetworkEvent>,
        blockchain: Arc<RwLock<Blockchain>>,
        mempool: Arc<Mempool>,
        consensus: ProofOfWork,
    ) {
        while let Some(event) = receiver.recv().await {
            match event {
                NetworkEvent::PeerConnected(peer_id) => {
                    info!("Peer connected: {}", peer_id);
                }
                NetworkEvent::PeerDisconnected(peer_id) => {
                    info!("Peer disconnected: {}", peer_id);
                }
                NetworkEvent::MessageReceived { peer_id, message } => {
                    if let Err(e) = Self::handle_network_message(
                        peer_id,
                        message,
                        &blockchain,
                        &mempool,
                        &consensus,
                    ).await {
                        error!("Failed to handle network message: {}", e);
                    }
                }
                NetworkEvent::NewBlock(block) => {
                    if let Err(e) = Self::handle_new_block(
                        block,
                        &blockchain,
                        &mempool,
                        &consensus,
                    ).await {
                        error!("Failed to handle new block: {}", e);
                    }
                }
                NetworkEvent::NewTransaction(transaction) => {
                    if let Err(e) = Self::handle_new_transaction(
                        transaction,
                        &blockchain,
                        &mempool,
                    ).await {
                        error!("Failed to handle new transaction: {}", e);
                    }
                }
                NetworkEvent::SyncRequest { peer_id, start_height } => {
                    info!("Sync request from {} starting at height {}", peer_id, start_height);
                    // TODO: Implement sync response
                }
            }
        }
    }
    
    /// Handle network message
    async fn handle_network_message(
        _peer_id: libp2p::PeerId,
        message: NetworkMessage,
        blockchain: &Arc<RwLock<Blockchain>>,
        mempool: &Arc<Mempool>,
        consensus: &ProofOfWork,
    ) -> Result<()> {
        match message {
            NetworkMessage::GetBlockchainInfo => {
                // TODO: Send blockchain info response
            }
            NetworkMessage::GetBlocks { start_height, count } => {
                // TODO: Send blocks response
            }
            NetworkMessage::GetBlock(hash) => {
                // TODO: Send block response
            }
            NetworkMessage::NewBlock(block) => {
                Self::handle_new_block(block, blockchain, mempool, consensus).await?;
            }
            NetworkMessage::NewTransaction(transaction) => {
                Self::handle_new_transaction(transaction, blockchain, mempool).await?;
            }
            NetworkMessage::GetMempool => {
                // TODO: Send mempool response
            }
            NetworkMessage::Ping => {
                // TODO: Send pong response
            }
            _ => {
                // Handle other message types
            }
        }
        Ok(())
    }
    
    /// Handle new block
    async fn handle_new_block(
        block: Block,
        blockchain: &Arc<RwLock<Blockchain>>,
        mempool: &Arc<Mempool>,
        consensus: &ProofOfWork,
    ) -> Result<()> {
        info!("Received new block at height {}", block.header.height);
        
        // Validate and add block
        {
            let mut blockchain = blockchain.write().unwrap();
            let current_height = blockchain.get_height();
            let previous_block = if block.header.height > 0 {
                blockchain.get_block_by_height(block.header.height - 1)?
            } else {
                None
            };
            
            // Validate block
            consensus.validate_block(&block, previous_block.as_ref(), current_height)?;
            
            // Add block to blockchain
            blockchain.add_block(block.clone())?;
        }
        
        // Remove transactions from mempool
        mempool.remove_transactions(&block.transactions)?;
        
        info!("Added new block at height {}", block.header.height);
        Ok(())
    }
    
    /// Handle new transaction
    async fn handle_new_transaction(
        transaction: Transaction,
        blockchain: &Arc<RwLock<Blockchain>>,
        mempool: &Arc<Mempool>,
    ) -> Result<()> {
        info!("Received new transaction: {}", transaction.hash()?.to_hex());
        
        // Get UTXO set and current height
        let (utxo_set, current_height) = {
            let blockchain = blockchain.read().unwrap();
            (blockchain.get_utxo_set().clone(), blockchain.get_height())
        };
        
        // Add to mempool
        if let Err(e) = mempool.add_transaction(transaction.clone(), &utxo_set, current_height) {
            warn!("Failed to add transaction to mempool: {}", e);
        } else {
            info!("Added transaction to mempool");
        }
        
        Ok(())
    }
    
    /// Mining loop
    async fn mining_loop(
        blockchain: Arc<RwLock<Blockchain>>,
        mempool: Arc<Mempool>,
        consensus: ProofOfWork,
        mining_address: String,
    ) {
        info!("Starting mining loop");
        
        loop {
            // Get transactions from mempool
            let (utxo_set, current_height, prev_hash, difficulty) = {
                let blockchain = blockchain.read().unwrap();
                let utxo_set = blockchain.get_utxo_set().clone();
                let current_height = blockchain.get_height();
                let latest_block = blockchain.get_latest_block().unwrap();
                let prev_hash = latest_block.hash().unwrap();
                let difficulty = consensus.calculate_next_difficulty(
                    Some(&latest_block),
                    current_height,
                ).unwrap();
                
                (utxo_set, current_height, prev_hash, difficulty)
            };
            
            let transactions = mempool.get_transactions_for_mining(
                1000, // max transactions
                1024 * 1024, // max size (1MB)
                &utxo_set,
            );
            
            if transactions.is_empty() {
                // No transactions to mine, wait a bit
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                continue;
            }
            
            // Create coinbase transaction
            let block_reward = consensus.calculate_block_reward(current_height + 1);
            let coinbase_tx = Transaction::create_coinbase(
                current_height + 1,
                mining_address.clone(),
                block_reward,
                b"mined by rust-blockchain".to_vec(),
            );
            
            // Prepare transactions (coinbase first)
            let mut block_transactions = vec![coinbase_tx];
            block_transactions.extend(transactions);
            
            // Create and mine block
            match Block::new(
                current_height + 1,
                prev_hash,
                block_transactions,
                difficulty,
                0, // Initial nonce
            ) {
                Ok(mut block) => {
                    info!("Mining block at height {}", block.header.height);
                    
                    // Mine the block
                    match consensus.mine_block(block.header.clone()) {
                        Ok(mined_header) => {
                            block.header = mined_header;
                            
                            // Add block to blockchain
                            {
                                let mut blockchain = blockchain.write().unwrap();
                                if let Err(e) = blockchain.add_block(block.clone()) {
                                    error!("Failed to add mined block: {}", e);
                                    continue;
                                }
                            }
                            
                            // Remove transactions from mempool
                            if let Err(e) = mempool.remove_transactions(&block.transactions) {
                                error!("Failed to remove transactions from mempool: {}", e);
                            }
                            
                            info!("Successfully mined block at height {}", block.header.height);
                            
                            // TODO: Broadcast block to network
                        }
                        Err(e) => {
                            error!("Failed to mine block: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to create block: {}", e);
                }
            }
            
            // Small delay before next mining attempt
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }
    
    /// Start RPC server
    async fn start_rpc_server(&self) -> Result<()> {
        // TODO: Implement RPC server
        info!("RPC server would start on port {}", self.config.rpc_port);
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let matches = Command::new("rust-blockchain-node")
        .version("1.0.0")
        .author("Rust Blockchain Team")
        .about("Blockchain node implementation in Rust")
        .arg(
            Arg::new("data-dir")
                .long("data-dir")
                .value_name("DIR")
                .help("Data directory for blockchain storage")
                .default_value("./data"),
        )
        .arg(
            Arg::new("listen")
                .long("listen")
                .value_name("ADDR")
                .help("Network listen address")
                .default_value("/ip4/0.0.0.0/tcp/8333"),
        )
        .arg(
            Arg::new("bootstrap")
                .long("bootstrap")
                .value_name("PEER")
                .help("Bootstrap peer address")
                .action(clap::ArgAction::Append),
        )
        .arg(
            Arg::new("mine")
                .long("mine")
                .help("Enable mining")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("mining-address")
                .long("mining-address")
                .value_name("ADDRESS")
                .help("Address to receive mining rewards")
                .requires("mine"),
        )
        .arg(
            Arg::new("rpc-port")
                .long("rpc-port")
                .value_name("PORT")
                .help("RPC server port")
                .default_value("8332"),
        )
        .arg(
            Arg::new("log-level")
                .long("log-level")
                .value_name("LEVEL")
                .help("Log level (trace, debug, info, warn, error)")
                .default_value("info"),
        )
        .get_matches();
    
    // Initialize logging
    let log_level = matches.get_one::<String>("log-level").unwrap();
    let filter = match log_level.as_str() {
        "trace" => tracing::Level::TRACE,
        "debug" => tracing::Level::DEBUG,
        "info" => tracing::Level::INFO,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };
    
    tracing_subscriber::fmt()
        .with_max_level(filter)
        .init();
    
    // Parse configuration
    let mut config = NodeConfig::default();
    config.data_dir = PathBuf::from(matches.get_one::<String>("data-dir").unwrap());
    config.listen_addr = matches.get_one::<String>("listen").unwrap().to_string();
    config.bootstrap_peers = matches
        .get_many::<String>("bootstrap")
        .unwrap_or_default()
        .map(|s| s.to_string())
        .collect();
    config.enable_mining = matches.get_flag("mine");
    config.mining_address = matches.get_one::<String>("mining-address").map(|s| s.to_string());
    config.rpc_port = matches.get_one::<String>("rpc-port").unwrap().parse()?;
    config.log_level = log_level.clone();
    
    // Create data directory if it doesn't exist
    std::fs::create_dir_all(&config.data_dir)?;
    
    info!("Starting node with config: {:?}", config);
    
    // Create and start node
    let mut node = Node::new(config).await?;
    node.start().await?;
    
    Ok(())
}