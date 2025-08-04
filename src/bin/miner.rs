//! Blockchain miner binary
//!
//! Dedicated mining tool that can connect to a blockchain node
//! and perform mining operations with configurable parameters.

use anyhow::Result;
use clap::{Arg, Command};
use rust_blockchain::{
    blockchain::Blockchain,
    consensus::ProofOfWork,
    mining::{Miner, MiningConfig},
    storage::Storage,
    transaction::Transaction,
    wallet::WalletManager,
};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::signal;
use tracing::{error, info, warn};
use tracing_subscriber;

/// Miner configuration
#[derive(Debug, Clone)]
struct MinerConfig {
    /// Data directory
    data_dir: PathBuf,
    /// Mining address (wallet name or address)
    mining_address: String,
    /// Number of mining threads
    threads: usize,
    /// Mining intensity (0.0 to 1.0)
    intensity: f64,
    /// Maximum mining time per block (seconds)
    max_mining_time: u64,
    /// Minimum transactions to include in block
    min_transactions: usize,
    /// Maximum transactions to include in block
    max_transactions: usize,
    /// Log level
    log_level: String,
    /// Solo mining mode (vs pool mining)
    solo_mining: bool,
    /// Pool address (if not solo mining)
    pool_address: Option<String>,
}

impl Default for MinerConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data"),
            mining_address: String::new(),
            threads: num_cpus::get(),
            intensity: 1.0,
            max_mining_time: 600, // 10 minutes
            min_transactions: 1,   // At least coinbase
            max_transactions: 1000,
            log_level: "info".to_string(),
            solo_mining: true,
            pool_address: None,
        }
    }
}

/// Mining application
struct MiningApp {
    config: MinerConfig,
    miner: Miner,
    blockchain: Arc<RwLock<Blockchain>>,
    consensus: ProofOfWork,
    wallet_manager: WalletManager,
    mining_address: String,
    start_time: Instant,
    blocks_mined: u64,
    total_hash_attempts: u64,
}

impl MiningApp {
    /// Create a new mining application
    async fn new(config: MinerConfig) -> Result<Self> {
        // Initialize storage
        let storage_path = config.data_dir.join("blockchain");
        let storage = Storage::new(&storage_path)?;
        
        // Load or create blockchain
        let blockchain = if storage.is_empty()? {
            info!("Creating new blockchain for mining");
            Blockchain::new(storage)?
        } else {
            info!("Loading existing blockchain");
            Blockchain::load(storage)?
        };
        
        // Initialize wallet manager
        let wallet_path = config.data_dir.join("wallets");
        let wallet_manager = WalletManager::new(&wallet_path)?;
        
        // Resolve mining address
        let mining_address = if let Some(wallet) = wallet_manager.get_wallet(&config.mining_address) {
            wallet.address
        } else if rust_blockchain::utils::is_valid_address(&config.mining_address) {
            config.mining_address.clone()
        } else {
            return Err(anyhow::anyhow!(
                "Invalid mining address: '{}'. Must be a valid address or wallet name.",
                config.mining_address
            ));
        };
        
        // Initialize miner
        let mining_config = MiningConfig {
            threads: config.threads,
            intensity: config.intensity,
            max_mining_time: Duration::from_secs(config.max_mining_time),
            target_block_time: Duration::from_secs(600), // 10 minutes
        };
        
        let miner = Miner::new(mining_config);
        let consensus = ProofOfWork::default();
        
        Ok(Self {
            config,
            miner,
            blockchain: Arc::new(RwLock::new(blockchain)),
            consensus,
            wallet_manager,
            mining_address,
            start_time: Instant::now(),
            blocks_mined: 0,
            total_hash_attempts: 0,
        })
    }
    
    /// Start mining
    async fn start_mining(&mut self) -> Result<()> {
        info!("Starting mining with configuration:");
        info!("  Mining Address: {}", self.mining_address);
        info!("  Threads: {}", self.config.threads);
        info!("  Intensity: {:.1}%", self.config.intensity * 100.0);
        info!("  Max Mining Time: {}s", self.config.max_mining_time);
        info!("  Solo Mining: {}", self.config.solo_mining);
        
        // Setup graceful shutdown
        let shutdown_signal = signal::ctrl_c();
        
        // Mining loop
        loop {
            tokio::select! {
                _ = shutdown_signal => {
                    info!("Received shutdown signal, stopping mining...");
                    break;
                }
                result = self.mine_next_block() => {
                    match result {
                        Ok(true) => {
                            self.blocks_mined += 1;
                            info!("Successfully mined block! Total blocks mined: {}", self.blocks_mined);
                            self.print_mining_stats();
                        }
                        Ok(false) => {
                            // No transactions to mine, wait a bit
                            tokio::time::sleep(Duration::from_secs(5)).await;
                        }
                        Err(e) => {
                            error!("Mining error: {}", e);
                            tokio::time::sleep(Duration::from_secs(10)).await;
                        }
                    }
                }
            }
        }
        
        self.print_final_stats();
        Ok(())
    }
    
    /// Mine the next block
    async fn mine_next_block(&mut self) -> Result<bool> {
        // Get current blockchain state
        let (current_height, prev_hash, difficulty, utxo_set) = {
            let blockchain = self.blockchain.read().unwrap();
            let current_height = blockchain.get_height();
            let latest_block = blockchain.get_latest_block()?;
            let prev_hash = latest_block.hash()?;
            let difficulty = self.consensus.calculate_next_difficulty(
                Some(&latest_block),
                current_height,
            )?;
            let utxo_set = blockchain.get_utxo_set().clone();
            
            (current_height, prev_hash, difficulty, utxo_set)
        };
        
        // Create coinbase transaction
        let block_height = current_height + 1;
        let block_reward = self.consensus.calculate_block_reward(block_height);
        let coinbase_tx = Transaction::create_coinbase(
            block_height,
            self.mining_address.clone(),
            block_reward,
            format!("Mined by rust-blockchain miner at height {}", block_height).into_bytes(),
        );
        
        // Prepare transactions for the block
        let mut transactions = vec![coinbase_tx];
        
        // Add transactions from mempool (if available)
        // For now, we'll just mine with coinbase transaction
        // In a real implementation, you'd get transactions from a mempool
        
        if transactions.len() < self.config.min_transactions {
            // Not enough transactions to mine
            return Ok(false);
        }
        
        // Limit transactions
        if transactions.len() > self.config.max_transactions {
            transactions.truncate(self.config.max_transactions);
        }
        
        info!("Mining block {} with {} transactions", block_height, transactions.len());
        
        // Create block
        let block = rust_blockchain::block::Block::new(
            block_height,
            prev_hash,
            transactions,
            difficulty,
            0, // Initial nonce
        )?;
        
        // Mine the block
        let mining_start = Instant::now();
        let mined_block = self.miner.mine_block_multithreaded(
            block,
            &self.consensus,
        ).await?;
        
        let mining_duration = mining_start.elapsed();
        let stats = self.miner.get_stats();
        self.total_hash_attempts += stats.total_attempts;
        
        info!(
            "Block mined in {:.2}s with {} attempts ({:.0} H/s)",
            mining_duration.as_secs_f64(),
            stats.total_attempts,
            stats.hash_rate
        );
        
        // Add block to blockchain
        {
            let mut blockchain = self.blockchain.write().unwrap();
            blockchain.add_block(mined_block)?;
        }
        
        Ok(true)
    }
    
    /// Print current mining statistics
    fn print_mining_stats(&self) {
        let elapsed = self.start_time.elapsed();
        let stats = self.miner.get_stats();
        
        let avg_block_time = if self.blocks_mined > 0 {
            elapsed.as_secs_f64() / self.blocks_mined as f64
        } else {
            0.0
        };
        
        let overall_hash_rate = if elapsed.as_secs_f64() > 0.0 {
            self.total_hash_attempts as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };
        
        info!("Mining Statistics:");
        info!("  Blocks Mined: {}", self.blocks_mined);
        info!("  Total Runtime: {:.1}s", elapsed.as_secs_f64());
        info!("  Average Block Time: {:.1}s", avg_block_time);
        info!("  Current Hash Rate: {:.0} H/s", stats.hash_rate);
        info!("  Overall Hash Rate: {:.0} H/s", overall_hash_rate);
        info!("  Total Hash Attempts: {}", self.total_hash_attempts);
    }
    
    /// Print final mining statistics
    fn print_final_stats(&self) {
        let elapsed = self.start_time.elapsed();
        
        println!("\n=== Final Mining Statistics ===");
        println!("Total Runtime: {:.1} seconds ({:.1} hours)", 
            elapsed.as_secs_f64(), 
            elapsed.as_secs_f64() / 3600.0
        );
        println!("Blocks Mined: {}", self.blocks_mined);
        println!("Total Hash Attempts: {}", self.total_hash_attempts);
        
        if elapsed.as_secs_f64() > 0.0 {
            let overall_hash_rate = self.total_hash_attempts as f64 / elapsed.as_secs_f64();
            println!("Average Hash Rate: {:.0} H/s", overall_hash_rate);
        }
        
        if self.blocks_mined > 0 {
            let avg_block_time = elapsed.as_secs_f64() / self.blocks_mined as f64;
            println!("Average Block Time: {:.1} seconds", avg_block_time);
            
            let total_reward = self.blocks_mined * 50 * 100_000_000; // Simplified
            println!("Total Rewards: {} satoshis ({:.8} BTC)", 
                total_reward, 
                rust_blockchain::utils::satoshis_to_btc(total_reward)
            );
        }
        
        println!("Mining Address: {}", self.mining_address);
        println!("Threads Used: {}", self.config.threads);
        println!("=================================\n");
    }
    
    /// Get current blockchain height
    fn get_blockchain_height(&self) -> u64 {
        self.blockchain.read().unwrap().get_height()
    }
    
    /// Check if mining should continue
    fn should_continue_mining(&self) -> bool {
        // Add any conditions for stopping mining
        // For example, maximum blocks, time limits, etc.
        true
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let matches = Command::new("rust-blockchain-miner")
        .version("1.0.0")
        .author("Rust Blockchain Team")
        .about("Blockchain miner for Rust Blockchain")
        .arg(
            Arg::new("data-dir")
                .long("data-dir")
                .value_name("DIR")
                .help("Data directory for blockchain storage")
                .default_value("./data"),
        )
        .arg(
            Arg::new("mining-address")
                .long("mining-address")
                .value_name("ADDRESS")
                .help("Mining address (wallet name or address)")
                .required(true),
        )
        .arg(
            Arg::new("threads")
                .long("threads")
                .value_name("COUNT")
                .help("Number of mining threads")
                .default_value(&num_cpus::get().to_string()),
        )
        .arg(
            Arg::new("intensity")
                .long("intensity")
                .value_name("PERCENT")
                .help("Mining intensity (0.0 to 1.0)")
                .default_value("1.0"),
        )
        .arg(
            Arg::new("max-time")
                .long("max-time")
                .value_name("SECONDS")
                .help("Maximum mining time per block")
                .default_value("600"),
        )
        .arg(
            Arg::new("min-transactions")
                .long("min-transactions")
                .value_name("COUNT")
                .help("Minimum transactions to include in block")
                .default_value("1"),
        )
        .arg(
            Arg::new("max-transactions")
                .long("max-transactions")
                .value_name("COUNT")
                .help("Maximum transactions to include in block")
                .default_value("1000"),
        )
        .arg(
            Arg::new("log-level")
                .long("log-level")
                .value_name("LEVEL")
                .help("Log level (trace, debug, info, warn, error)")
                .default_value("info"),
        )
        .arg(
            Arg::new("pool")
                .long("pool")
                .value_name("ADDRESS")
                .help("Mining pool address (enables pool mining)"),
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
    let mut config = MinerConfig::default();
    config.data_dir = PathBuf::from(matches.get_one::<String>("data-dir").unwrap());
    config.mining_address = matches.get_one::<String>("mining-address").unwrap().to_string();
    config.threads = matches.get_one::<String>("threads").unwrap().parse()?;
    config.intensity = matches.get_one::<String>("intensity").unwrap().parse()?;
    config.max_mining_time = matches.get_one::<String>("max-time").unwrap().parse()?;
    config.min_transactions = matches.get_one::<String>("min-transactions").unwrap().parse()?;
    config.max_transactions = matches.get_one::<String>("max-transactions").unwrap().parse()?;
    config.log_level = log_level.clone();
    
    if let Some(pool_address) = matches.get_one::<String>("pool") {
        config.solo_mining = false;
        config.pool_address = Some(pool_address.to_string());
    }
    
    // Validate configuration
    if config.threads == 0 {
        return Err(anyhow::anyhow!("Number of threads must be greater than 0"));
    }
    
    if config.intensity < 0.0 || config.intensity > 1.0 {
        return Err(anyhow::anyhow!("Intensity must be between 0.0 and 1.0"));
    }
    
    if config.min_transactions == 0 {
        return Err(anyhow::anyhow!("Minimum transactions must be at least 1 (for coinbase)"));
    }
    
    if config.max_transactions < config.min_transactions {
        return Err(anyhow::anyhow!("Maximum transactions must be >= minimum transactions"));
    }
    
    // Create data directory if it doesn't exist
    std::fs::create_dir_all(&config.data_dir)?;
    
    info!("Starting miner with configuration:");
    info!("  Data Directory: {:?}", config.data_dir);
    info!("  Mining Address: {}", config.mining_address);
    info!("  Threads: {}", config.threads);
    info!("  Intensity: {:.1}%", config.intensity * 100.0);
    info!("  Solo Mining: {}", config.solo_mining);
    
    // Create and start mining application
    let mut app = MiningApp::new(config).await?;
    app.start_mining().await?;
    
    Ok(())
}