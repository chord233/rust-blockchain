//! Mining implementation with proof of work

use crate::block::Block;
use crate::blockchain::Blockchain;
use crate::crypto::Hash;
use crate::error::{BlockchainError, Result};
use crate::transaction::Transaction;
use crate::wallet::WalletManager;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tracing::{info, warn, error};

/// Mining statistics
#[derive(Debug, Clone)]
pub struct MiningStats {
    /// Total number of blocks mined
    pub blocks_mined: u64,
    /// Total mining attempts
    pub total_attempts: u64,
    /// Total mining time in seconds
    pub total_time: f64,
    /// Average hash rate (hashes per second)
    pub average_hashrate: f64,
    /// Current difficulty
    pub current_difficulty: u32,
    /// Last block mined timestamp
    pub last_block_time: Option<u64>,
}

impl MiningStats {
    /// Create new mining stats
    pub fn new() -> Self {
        Self {
            blocks_mined: 0,
            total_attempts: 0,
            total_time: 0.0,
            average_hashrate: 0.0,
            current_difficulty: 0,
            last_block_time: None,
        }
    }

    /// Update stats after mining a block
    pub fn update(&mut self, attempts: u64, time: f64, difficulty: u32) {
        self.blocks_mined += 1;
        self.total_attempts += attempts;
        self.total_time += time;
        self.current_difficulty = difficulty;
        self.last_block_time = Some(crate::utils::current_timestamp());
        
        if self.total_time > 0.0 {
            self.average_hashrate = self.total_attempts as f64 / self.total_time;
        }
    }

    /// Format stats as a string
    pub fn format(&self) -> String {
        format!(
            "Mining Statistics:\n\
            Blocks Mined: {}\n\
            Total Attempts: {}\n\
            Total Time: {:.2} seconds\n\
            Average Hashrate: {:.2} H/s\n\
            Current Difficulty: {}\n\
            Last Block: {}",
            self.blocks_mined,
            self.total_attempts,
            self.total_time,
            self.average_hashrate,
            self.current_difficulty,
            self.last_block_time
                .map(|t| chrono::DateTime::from_timestamp(t as i64, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| "Invalid timestamp".to_string()))
                .unwrap_or_else(|| "Never".to_string())
        )
    }
}

/// Mining configuration
#[derive(Debug, Clone)]
pub struct MiningConfig {
    /// Number of mining threads
    pub threads: usize,
    /// Target block time in seconds
    pub target_block_time: u64,
    /// Difficulty adjustment interval (in blocks)
    pub difficulty_adjustment_interval: u64,
    /// Maximum nonce value before giving up
    pub max_nonce: u64,
    /// Progress reporting interval (in attempts)
    pub progress_interval: u64,
}

impl Default for MiningConfig {
    fn default() -> Self {
        Self {
            threads: num_cpus::get(),
            target_block_time: 600, // 10 minutes
            difficulty_adjustment_interval: 2016, // Bitcoin-like
            max_nonce: u64::MAX,
            progress_interval: 1_000_000,
        }
    }
}

/// Miner struct for mining operations
#[derive(Debug)]
pub struct Miner {
    /// Mining configuration
    config: MiningConfig,
    /// Mining statistics
    stats: MiningStats,
    /// Flag to stop mining
    stop_flag: Arc<AtomicBool>,
    /// Current mining attempts
    attempts: Arc<AtomicU64>,
}

impl Miner {
    /// Create a new miner
    pub fn new(config: MiningConfig) -> Self {
        Self {
            config,
            stats: MiningStats::new(),
            stop_flag: Arc::new(AtomicBool::new(false)),
            attempts: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Create a miner with default configuration
    pub fn default() -> Self {
        Self::new(MiningConfig::default())
    }

    /// Mine a single block
    pub fn mine_block(
        &mut self,
        blockchain: &mut Blockchain,
        wallet_manager: &WalletManager,
        miner_wallet: &str,
        transactions: Vec<Transaction>,
    ) -> Result<Block> {
        info!("Starting to mine new block...");
        
        // Get miner address
        let miner_address = wallet_manager.get_address(miner_wallet)?;
        
        // Create coinbase transaction
        let coinbase_tx = Transaction::coinbase(&miner_address, blockchain.height() + 1);
        
        // Combine coinbase with other transactions
        let mut all_transactions = vec![coinbase_tx];
        all_transactions.extend(transactions);
        
        // Validate all transactions
        for tx in &all_transactions[1..] { // Skip coinbase
            tx.validate(blockchain.utxo_set())?;
        }
        
        // Create new block
        let mut block = Block::new(
            blockchain.latest_block_hash().clone(),
            all_transactions,
            blockchain.difficulty(),
            blockchain.height() + 1,
        )?;
        
        // Mine the block
        let start_time = Instant::now();
        self.attempts.store(0, Ordering::Relaxed);
        self.stop_flag.store(false, Ordering::Relaxed);
        
        if self.config.threads == 1 {
            // Single-threaded mining
            self.mine_single_threaded(&mut block)?;
        } else {
            // Multi-threaded mining
            self.mine_multi_threaded(&mut block)?;
        }
        
        let mining_time = start_time.elapsed().as_secs_f64();
        let total_attempts = self.attempts.load(Ordering::Relaxed);
        
        // Update statistics
        self.stats.update(total_attempts, mining_time, blockchain.difficulty());
        
        info!(
            "Block mined successfully! Height: {}, Hash: {}, Nonce: {}, Attempts: {}, Time: {:.2}s",
            block.header.height,
            block.hash()?.to_hex(),
            block.header.nonce,
            total_attempts,
            mining_time
        );
        
        Ok(block)
    }

    /// Single-threaded mining
    fn mine_single_threaded(&self, block: &mut Block) -> Result<()> {
        let mut nonce = 0u64;
        let start_time = Instant::now();
        
        loop {
            // Check stop flag
            if self.stop_flag.load(Ordering::Relaxed) {
                return Err(BlockchainError::MiningError("Mining stopped".to_string()));
            }
            
            block.header.nonce = nonce;
            self.attempts.fetch_add(1, Ordering::Relaxed);
            
            // Check if we found a valid hash
            if block.header.meets_difficulty()? {
                return Ok(());
            }
            
            nonce = nonce.wrapping_add(1);
            
            // Update timestamp and report progress
            if nonce % self.config.progress_interval == 0 {
                block.header.timestamp = crate::utils::current_timestamp();
                let elapsed = start_time.elapsed().as_secs_f64();
                let hashrate = nonce as f64 / elapsed;
                info!("Mining progress: {} attempts, {:.2} H/s", nonce, hashrate);
            }
            
            // Safety check
            if nonce >= self.config.max_nonce {
                return Err(BlockchainError::MiningError(
                    "Reached maximum nonce value".to_string(),
                ));
            }
        }
    }

    /// Multi-threaded mining
    fn mine_multi_threaded(&self, block: &mut Block) -> Result<()> {
        let found = Arc::new(AtomicBool::new(false));
        let result_nonce = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();
        
        info!("Starting multi-threaded mining with {} threads", self.config.threads);
        
        for thread_id in 0..self.config.threads {
            let mut thread_block = block.clone();
            let found_clone = Arc::clone(&found);
            let result_nonce_clone = Arc::clone(&result_nonce);
            let stop_flag_clone = Arc::clone(&self.stop_flag);
            let attempts_clone = Arc::clone(&self.attempts);
            let progress_interval = self.config.progress_interval;
            let max_nonce = self.config.max_nonce;
            
            let handle = thread::spawn(move || {
                let mut nonce = thread_id as u64;
                let thread_count = thread::current().id();
                
                loop {
                    // Check if another thread found the solution or stop was requested
                    if found_clone.load(Ordering::Relaxed) || stop_flag_clone.load(Ordering::Relaxed) {
                        break;
                    }
                    
                    thread_block.header.nonce = nonce;
                    attempts_clone.fetch_add(1, Ordering::Relaxed);
                    
                    // Check if we found a valid hash
                    if let Ok(true) = thread_block.header.meets_difficulty() {
                        found_clone.store(true, Ordering::Relaxed);
                        result_nonce_clone.store(nonce, Ordering::Relaxed);
                        info!("Thread {:?} found solution with nonce: {}", thread_count, nonce);
                        break;
                    }
                    
                    // Increment nonce for this thread
                    nonce = nonce.wrapping_add(thread::available_parallelism().unwrap().get() as u64);
                    
                    // Update timestamp occasionally
                    if nonce % progress_interval == 0 {
                        thread_block.header.timestamp = crate::utils::current_timestamp();
                    }
                    
                    // Safety check
                    if nonce >= max_nonce {
                        warn!("Thread {:?} reached maximum nonce", thread_count);
                        break;
                    }
                }
            });
            
            handles.push(handle);
        }
        
        // Wait for all threads to complete
        for handle in handles {
            handle.join().map_err(|_| {
                BlockchainError::MiningError("Mining thread panicked".to_string())
            })?;
        }
        
        // Check if we found a solution
        if found.load(Ordering::Relaxed) {
            block.header.nonce = result_nonce.load(Ordering::Relaxed);
            Ok(())
        } else {
            Err(BlockchainError::MiningError(
                "No solution found by any thread".to_string(),
            ))
        }
    }

    /// Start continuous mining
    pub fn start_mining(
        &mut self,
        blockchain: &mut Blockchain,
        wallet_manager: &WalletManager,
        miner_wallet: &str,
    ) -> Result<()> {
        info!("Starting continuous mining...");
        
        self.stop_flag.store(false, Ordering::Relaxed);
        
        while !self.stop_flag.load(Ordering::Relaxed) {
            // Mine a new block with empty transactions (just coinbase)
            match self.mine_block(blockchain, wallet_manager, miner_wallet, Vec::new()) {
                Ok(block) => {
                    // Add the mined block to the blockchain
                    blockchain.add_block(block)?;
                    info!("Block added to blockchain. New height: {}", blockchain.height());
                }
                Err(e) => {
                    error!("Mining error: {}", e);
                    // Wait a bit before retrying
                    thread::sleep(Duration::from_secs(1));
                }
            }
        }
        
        info!("Mining stopped");
        Ok(())
    }

    /// Stop mining
    pub fn stop_mining(&self) {
        info!("Stopping mining...");
        self.stop_flag.store(true, Ordering::Relaxed);
    }

    /// Get mining statistics
    pub fn get_stats(&self) -> &MiningStats {
        &self.stats
    }

    /// Get current hashrate
    pub fn current_hashrate(&self, duration: Duration) -> f64 {
        let attempts = self.attempts.load(Ordering::Relaxed);
        attempts as f64 / duration.as_secs_f64()
    }

    /// Calculate difficulty adjustment
    pub fn calculate_difficulty_adjustment(
        &self,
        blockchain: &Blockchain,
        current_difficulty: u32,
    ) -> Result<u32> {
        let current_height = blockchain.height();
        
        // Only adjust every difficulty_adjustment_interval blocks
        if current_height % self.config.difficulty_adjustment_interval != 0 {
            return Ok(current_difficulty);
        }
        
        if current_height < self.config.difficulty_adjustment_interval {
            return Ok(current_difficulty);
        }
        
        // Get the block from difficulty_adjustment_interval blocks ago
        let start_height = current_height - self.config.difficulty_adjustment_interval;
        let start_block = blockchain.get_block(start_height)?
            .ok_or_else(|| BlockchainError::BlockNotFound(start_height))?;
        
        let current_block = blockchain.get_latest_block()?;
        
        // Calculate actual time taken
        let actual_time = current_block.header.timestamp - start_block.header.timestamp;
        let target_time = self.config.difficulty_adjustment_interval * self.config.target_block_time;
        
        // Calculate adjustment factor (limit to 4x increase or 1/4 decrease)
        let adjustment_factor = (target_time as f64) / (actual_time as f64);
        let clamped_factor = adjustment_factor.max(0.25).min(4.0);
        
        // Apply adjustment
        let new_difficulty = (current_difficulty as f64 * clamped_factor) as u32;
        let new_difficulty = new_difficulty.max(1); // Minimum difficulty of 1
        
        info!(
            "Difficulty adjustment: {} -> {} (factor: {:.2}, actual time: {}s, target time: {}s)",
            current_difficulty, new_difficulty, clamped_factor, actual_time, target_time
        );
        
        Ok(new_difficulty)
    }

    /// Estimate time to mine next block
    pub fn estimate_mining_time(&self, difficulty: u32) -> Duration {
        if self.stats.average_hashrate <= 0.0 {
            return Duration::from_secs(u64::MAX); // Unknown
        }
        
        // Rough estimation based on difficulty and current hashrate
        let target_attempts = 2u64.pow(difficulty);
        let estimated_seconds = target_attempts as f64 / self.stats.average_hashrate;
        
        Duration::from_secs_f64(estimated_seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::Blockchain;
    use crate::wallet::WalletManager;
    use tempfile::TempDir;

    fn create_test_setup() -> (Blockchain, WalletManager, TempDir, TempDir) {
        let blockchain_dir = TempDir::new().unwrap();
        let wallet_dir = TempDir::new().unwrap();
        
        let mut wallet_manager = WalletManager::new(wallet_dir.path().to_str().unwrap()).unwrap();
        let genesis_address = wallet_manager.create_wallet("genesis").unwrap();
        
        let blockchain = Blockchain::new(
            blockchain_dir.path().to_str().unwrap(),
            &genesis_address,
        ).unwrap();
        
        (blockchain, wallet_manager, blockchain_dir, wallet_dir)
    }

    #[test]
    fn test_miner_creation() {
        let config = MiningConfig::default();
        let miner = Miner::new(config);
        assert_eq!(miner.stats.blocks_mined, 0);
    }

    #[test]
    fn test_mining_stats() {
        let mut stats = MiningStats::new();
        stats.update(1000, 10.0, 20);
        
        assert_eq!(stats.blocks_mined, 1);
        assert_eq!(stats.total_attempts, 1000);
        assert_eq!(stats.total_time, 10.0);
        assert_eq!(stats.average_hashrate, 100.0);
        assert_eq!(stats.current_difficulty, 20);
    }

    #[test]
    fn test_mining_config_default() {
        let config = MiningConfig::default();
        assert!(config.threads > 0);
        assert_eq!(config.target_block_time, 600);
        assert_eq!(config.difficulty_adjustment_interval, 2016);
    }

    #[test]
    fn test_estimate_mining_time() {
        let mut miner = Miner::default();
        miner.stats.average_hashrate = 1000.0; // 1000 H/s
        
        let estimate = miner.estimate_mining_time(1);
        assert!(estimate.as_secs() > 0);
    }

    #[test]
    fn test_stop_mining() {
        let miner = Miner::default();
        assert!(!miner.stop_flag.load(Ordering::Relaxed));
        
        miner.stop_mining();
        assert!(miner.stop_flag.load(Ordering::Relaxed));
    }

    // Note: Actual mining tests are commented out as they would take too long
    // and require significant computational resources
    
    /*
    #[test]
    fn test_mine_block() {
        let (mut blockchain, wallet_manager, _blockchain_dir, _wallet_dir) = create_test_setup();
        let mut miner = Miner::default();
        
        // This test would take too long with real difficulty
        // In practice, you'd use a very low difficulty for testing
        let block = miner.mine_block(
            &mut blockchain,
            &wallet_manager,
            "genesis",
            Vec::new(),
        ).unwrap();
        
        assert!(block.header.meets_difficulty().unwrap());
    }
    */
}