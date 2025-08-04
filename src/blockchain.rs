//! Blockchain implementation with UTXO model

use crate::block::Block;
use crate::crypto::Hash;
use crate::error::{BlockchainError, Result};
use crate::storage::Storage;
use crate::transaction::{Transaction, UTXO};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn, error};

/// Blockchain statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainStats {
    /// Total number of blocks
    pub block_count: u64,
    /// Current blockchain height
    pub height: u64,
    /// Total number of transactions
    pub transaction_count: u64,
    /// Total number of UTXOs
    pub utxo_count: u64,
    /// Total value in circulation
    pub total_value: u64,
    /// Current difficulty
    pub difficulty: u32,
    /// Hash of the latest block
    pub latest_block_hash: Hash,
}

/// The main blockchain structure
#[derive(Debug)]
pub struct Blockchain {
    /// Storage backend
    storage: Storage,
    /// Current UTXO set
    utxo_set: HashMap<String, UTXO>,
    /// Current blockchain height
    height: u64,
    /// Hash of the latest block
    latest_block_hash: Hash,
    /// Current mining difficulty
    difficulty: u32,
}

impl Blockchain {
    /// Create a new blockchain with genesis block
    pub fn new(storage_path: &str, genesis_address: &str) -> Result<Self> {
        let storage = Storage::new(storage_path)?;
        
        // Check if blockchain already exists
        if let Ok(Some(_)) = storage.get_block_by_height(0) {
            // Load existing blockchain
            Self::load_existing(storage)
        } else {
            // Create new blockchain with genesis block
            Self::create_new(storage, genesis_address)
        }
    }

    /// Load an existing blockchain from storage
    fn load_existing(storage: Storage) -> Result<Self> {
        info!("Loading existing blockchain...");
        
        // Get the latest block height
        let height = storage.get_latest_height()?;
        
        // Get the latest block
        let latest_block = storage.get_block_by_height(height)?
            .ok_or_else(|| BlockchainError::BlockNotFound(height))?;
        
        let latest_block_hash = latest_block.hash()?;
        
        // Rebuild UTXO set
        let utxo_set = Self::rebuild_utxo_set(&storage, height)?;
        
        info!("Loaded blockchain with {} blocks and {} UTXOs", 
              height + 1, utxo_set.len());
        
        Ok(Self {
            storage,
            utxo_set,
            height,
            latest_block_hash,
            difficulty: crate::DIFFICULTY,
        })
    }

    /// Create a new blockchain with genesis block
    fn create_new(storage: Storage, genesis_address: &str) -> Result<Self> {
        info!("Creating new blockchain with genesis address: {}", genesis_address);
        
        // Create genesis block
        let mut genesis_block = Block::genesis(genesis_address)?;
        
        // Mine the genesis block
        genesis_block.mine()?;
        
        let genesis_hash = genesis_block.hash()?;
        
        // Store genesis block
        storage.store_block(&genesis_block)?;
        storage.set_latest_height(0)?;
        
        // Initialize UTXO set with genesis coinbase
        let mut utxo_set = HashMap::new();
        let coinbase_tx = genesis_block.coinbase_transaction().unwrap();
        let coinbase_hash = coinbase_tx.hash()?;
        
        for (index, output) in coinbase_tx.outputs.iter().enumerate() {
            let utxo = UTXO::new(
                coinbase_hash.clone(),
                index as u32,
                output.clone(),
                0, // genesis block height
            );
            utxo_set.insert(utxo.id(), utxo);
        }
        
        info!("Created genesis block with hash: {}", genesis_hash.to_hex());
        
        Ok(Self {
            storage,
            utxo_set,
            height: 0,
            latest_block_hash: genesis_hash,
            difficulty: crate::DIFFICULTY,
        })
    }

    /// Rebuild UTXO set by scanning all blocks
    fn rebuild_utxo_set(storage: &Storage, height: u64) -> Result<HashMap<String, UTXO>> {
        info!("Rebuilding UTXO set...");
        let mut utxo_set = HashMap::new();
        
        for block_height in 0..=height {
            let block = storage.get_block_by_height(block_height)?
                .ok_or_else(|| BlockchainError::BlockNotFound(block_height))?;
            
            for transaction in &block.transactions {
                let tx_hash = transaction.hash()?;
                
                // Remove spent UTXOs
                if !transaction.is_coinbase() {
                    for input in &transaction.inputs {
                        let utxo_id = format!("{}:{}", input.prev_tx_hash.to_hex(), input.output_index);
                        utxo_set.remove(&utxo_id);
                    }
                }
                
                // Add new UTXOs
                for (index, output) in transaction.outputs.iter().enumerate() {
                    let utxo = UTXO::new(
                        tx_hash.clone(),
                        index as u32,
                        output.clone(),
                        block_height,
                    );
                    utxo_set.insert(utxo.id(), utxo);
                }
            }
        }
        
        info!("UTXO set rebuilt with {} entries", utxo_set.len());
        Ok(utxo_set)
    }

    /// Add a new block to the blockchain
    pub fn add_block(&mut self, mut block: Block) -> Result<()> {
        // Validate block
        self.validate_new_block(&block)?;
        
        // Mine the block if not already mined
        if !block.header.meets_difficulty()? {
            block.mine()?;
        }
        
        let block_hash = block.hash()?;
        let block_height = block.header.height;
        
        info!("Adding block #{} with hash: {}", block_height, block_hash.to_hex());
        
        // Update UTXO set
        self.update_utxo_set(&block)?;
        
        // Store block
        self.storage.store_block(&block)?;
        self.storage.set_latest_height(block_height)?;
        
        // Update blockchain state
        self.height = block_height;
        self.latest_block_hash = block_hash;
        
        info!("Block #{} added successfully", block_height);
        Ok(())
    }

    /// Validate a new block before adding it to the chain
    fn validate_new_block(&self, block: &Block) -> Result<()> {
        // Check height
        if block.header.height != self.height + 1 {
            return Err(BlockchainError::BlockValidation(
                format!("Invalid block height: expected {}, got {}", 
                       self.height + 1, block.header.height)
            ));
        }
        
        // Check previous block hash
        if block.header.prev_block_hash != self.latest_block_hash {
            return Err(BlockchainError::BlockValidation(
                "Invalid previous block hash".to_string()
            ));
        }
        
        // Validate block structure and transactions
        block.validate(&self.utxo_set)?;
        
        Ok(())
    }

    /// Update UTXO set with transactions from a new block
    fn update_utxo_set(&mut self, block: &Block) -> Result<()> {
        for transaction in &block.transactions {
            let tx_hash = transaction.hash()?;
            
            // Remove spent UTXOs (except for coinbase)
            if !transaction.is_coinbase() {
                for input in &transaction.inputs {
                    let utxo_id = format!("{}:{}", input.prev_tx_hash.to_hex(), input.output_index);
                    if self.utxo_set.remove(&utxo_id).is_none() {
                        warn!("UTXO {} not found when processing transaction {}", 
                              utxo_id, tx_hash.to_hex());
                    }
                }
            }
            
            // Add new UTXOs
            for (index, output) in transaction.outputs.iter().enumerate() {
                let utxo = UTXO::new(
                    tx_hash.clone(),
                    index as u32,
                    output.clone(),
                    block.header.height,
                );
                self.utxo_set.insert(utxo.id(), utxo);
            }
        }
        
        Ok(())
    }

    /// Get the balance for a given address
    pub fn get_balance(&self, address: &str) -> u64 {
        self.utxo_set
            .values()
            .filter(|utxo| utxo.output.address == address)
            .map(|utxo| utxo.output.value)
            .sum()
    }

    /// Get UTXOs for a given address
    pub fn get_utxos_for_address(&self, address: &str) -> Vec<&UTXO> {
        self.utxo_set
            .values()
            .filter(|utxo| utxo.output.address == address)
            .collect()
    }

    /// Find UTXOs to spend for a given amount
    pub fn find_spendable_utxos(&self, address: &str, amount: u64) -> Result<(Vec<&UTXO>, u64)> {
        let mut selected_utxos = Vec::new();
        let mut total_value = 0u64;
        
        let mut available_utxos: Vec<&UTXO> = self.get_utxos_for_address(address);
        // Sort by value (largest first) for better coin selection
        available_utxos.sort_by(|a, b| b.output.value.cmp(&a.output.value));
        
        for utxo in available_utxos {
            selected_utxos.push(utxo);
            total_value += utxo.output.value;
            
            if total_value >= amount {
                return Ok((selected_utxos, total_value));
            }
        }
        
        Err(BlockchainError::InsufficientFunds {
            required: amount,
            available: total_value,
        })
    }

    /// Get a block by height
    pub fn get_block(&self, height: u64) -> Result<Option<Block>> {
        self.storage.get_block_by_height(height)
    }

    /// Get a block by hash
    pub fn get_block_by_hash(&self, hash: &Hash) -> Result<Option<Block>> {
        self.storage.get_block_by_hash(hash)
    }

    /// Get the latest block
    pub fn get_latest_block(&self) -> Result<Block> {
        self.get_block(self.height)?
            .ok_or_else(|| BlockchainError::BlockNotFound(self.height))
    }

    /// Get blockchain statistics
    pub fn get_stats(&self) -> Result<BlockchainStats> {
        let transaction_count = self.count_total_transactions()?;
        let total_value = self.utxo_set.values().map(|utxo| utxo.output.value).sum();
        
        Ok(BlockchainStats {
            block_count: self.height + 1,
            height: self.height,
            transaction_count,
            utxo_count: self.utxo_set.len() as u64,
            total_value,
            difficulty: self.difficulty,
            latest_block_hash: self.latest_block_hash.clone(),
        })
    }

    /// Count total transactions in the blockchain
    fn count_total_transactions(&self) -> Result<u64> {
        let mut count = 0u64;
        
        for height in 0..=self.height {
            if let Some(block) = self.get_block(height)? {
                count += block.transactions.len() as u64;
            }
        }
        
        Ok(count)
    }

    /// Validate the entire blockchain
    pub fn validate_chain(&self) -> Result<()> {
        info!("Validating entire blockchain...");
        
        let mut prev_hash = Hash::zero();
        let mut utxo_set = HashMap::new();
        
        for height in 0..=self.height {
            let block = self.get_block(height)?
                .ok_or_else(|| BlockchainError::BlockNotFound(height))?;
            
            // Check block linkage
            if height > 0 && block.header.prev_block_hash != prev_hash {
                return Err(BlockchainError::BlockValidation(
                    format!("Block {} has invalid previous hash", height)
                ));
            }
            
            // Validate block
            block.validate(&utxo_set)?;
            
            // Update UTXO set
            for transaction in &block.transactions {
                let tx_hash = transaction.hash()?;
                
                // Remove spent UTXOs
                if !transaction.is_coinbase() {
                    for input in &transaction.inputs {
                        let utxo_id = format!("{}:{}", input.prev_tx_hash.to_hex(), input.output_index);
                        utxo_set.remove(&utxo_id);
                    }
                }
                
                // Add new UTXOs
                for (index, output) in transaction.outputs.iter().enumerate() {
                    let utxo = UTXO::new(
                        tx_hash.clone(),
                        index as u32,
                        output.clone(),
                        height,
                    );
                    utxo_set.insert(utxo.id(), utxo);
                }
            }
            
            prev_hash = block.hash()?;
        }
        
        info!("Blockchain validation completed successfully");
        Ok(())
    }

    /// Print the entire blockchain
    pub fn print_chain(&self) -> Result<()> {
        println!("\n=== BLOCKCHAIN ===\n");
        
        for height in 0..=self.height {
            let block = self.get_block(height)?
                .ok_or_else(|| BlockchainError::BlockNotFound(height))?;
            
            println!("{}", block.stats()?);
            
            // Print transaction details
            for (i, tx) in block.transactions.iter().enumerate() {
                let tx_hash = tx.hash()?;
                println!("  Transaction #{}: {}", i, tx_hash.to_hex());
                
                if tx.is_coinbase() {
                    println!("    Type: Coinbase");
                } else {
                    println!("    Inputs: {}", tx.inputs.len());
                    for (j, input) in tx.inputs.iter().enumerate() {
                        println!("      Input #{}: {}:{}", j, 
                                input.prev_tx_hash.to_hex(), input.output_index);
                    }
                }
                
                println!("    Outputs: {}", tx.outputs.len());
                for (j, output) in tx.outputs.iter().enumerate() {
                    println!("      Output #{}: {} satoshis -> {}", 
                            j, output.value, output.address);
                }
                
                println!("    Fee: {} satoshis", tx.fee(&self.utxo_set));
            }
            
            println!();
        }
        
        // Print statistics
        let stats = self.get_stats()?;
        println!("=== STATISTICS ===\n");
        println!("Blocks: {}", stats.block_count);
        println!("Height: {}", stats.height);
        println!("Transactions: {}", stats.transaction_count);
        println!("UTXOs: {}", stats.utxo_count);
        println!("Total Value: {} satoshis ({:.8} BTC)", 
                stats.total_value, stats.total_value as f64 / 100_000_000.0);
        println!("Difficulty: {}", stats.difficulty);
        println!("Latest Hash: {}", stats.latest_block_hash.to_hex());
        
        Ok(())
    }

    /// Get current height
    pub fn height(&self) -> u64 {
        self.height
    }

    /// Get current difficulty
    pub fn difficulty(&self) -> u32 {
        self.difficulty
    }

    /// Get latest block hash
    pub fn latest_block_hash(&self) -> &Hash {
        &self.latest_block_hash
    }

    /// Get UTXO set
    pub fn utxo_set(&self) -> &HashMap<String, UTXO> {
        &self.utxo_set
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_blockchain() -> (Blockchain, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let blockchain = Blockchain::new(
            temp_dir.path().to_str().unwrap(),
            "test_genesis_address"
        ).unwrap();
        (blockchain, temp_dir)
    }

    #[test]
    fn test_blockchain_creation() {
        let (blockchain, _temp_dir) = create_test_blockchain();
        assert_eq!(blockchain.height(), 0);
        assert!(blockchain.get_balance("test_genesis_address") > 0);
    }

    #[test]
    fn test_blockchain_stats() {
        let (blockchain, _temp_dir) = create_test_blockchain();
        let stats = blockchain.get_stats().unwrap();
        assert_eq!(stats.block_count, 1);
        assert_eq!(stats.height, 0);
        assert_eq!(stats.transaction_count, 1);
        assert_eq!(stats.utxo_count, 1);
    }

    #[test]
    fn test_get_balance() {
        let (blockchain, _temp_dir) = create_test_blockchain();
        let balance = blockchain.get_balance("test_genesis_address");
        assert_eq!(balance, crate::BLOCK_REWARD);
        
        let zero_balance = blockchain.get_balance("nonexistent_address");
        assert_eq!(zero_balance, 0);
    }

    #[test]
    fn test_find_spendable_utxos() {
        let (blockchain, _temp_dir) = create_test_blockchain();
        
        // Should find UTXOs for genesis address
        let result = blockchain.find_spendable_utxos("test_genesis_address", 1000);
        assert!(result.is_ok());
        
        // Should fail for non-existent address
        let result = blockchain.find_spendable_utxos("nonexistent_address", 1000);
        assert!(result.is_err());
    }

    #[test]
    fn test_blockchain_validation() {
        let (blockchain, _temp_dir) = create_test_blockchain();
        assert!(blockchain.validate_chain().is_ok());
    }

    #[test]
    fn test_get_latest_block() {
        let (blockchain, _temp_dir) = create_test_blockchain();
        let latest_block = blockchain.get_latest_block().unwrap();
        assert!(latest_block.is_genesis());
        assert_eq!(latest_block.header.height, 0);
    }
}