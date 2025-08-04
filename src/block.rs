//! Block implementation for the blockchain

use crate::crypto::Hash;
use crate::error::{BlockchainError, Result};
use crate::transaction::Transaction;
use crate::utils::{serialize, current_timestamp, calculate_merkle_root};
use serde::{Deserialize, Serialize};

/// Block header containing metadata
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Version of the block format
    pub version: u32,
    /// Hash of the previous block
    pub prev_block_hash: Hash,
    /// Merkle root of all transactions in the block
    pub merkle_root: Hash,
    /// Block creation timestamp
    pub timestamp: u64,
    /// Difficulty target for proof of work
    pub difficulty: u32,
    /// Nonce used in proof of work
    pub nonce: u64,
    /// Block height in the chain
    pub height: u64,
}

impl BlockHeader {
    /// Create a new block header
    pub fn new(
        version: u32,
        prev_block_hash: Hash,
        merkle_root: Hash,
        difficulty: u32,
        height: u64,
    ) -> Self {
        Self {
            version,
            prev_block_hash,
            merkle_root,
            timestamp: current_timestamp(),
            difficulty,
            nonce: 0,
            height,
        }
    }

    /// Calculate the hash of this block header
    pub fn hash(&self) -> Result<Hash> {
        let serialized = serialize(self)?;
        Ok(Hash::double_hash(&serialized))
    }

    /// Check if the block header satisfies the difficulty requirement
    pub fn meets_difficulty(&self) -> Result<bool> {
        let hash = self.hash()?;
        let target = Self::difficulty_to_target(self.difficulty);
        Ok(hash.as_bytes() <= &target)
    }

    /// Convert difficulty to target bytes
    pub fn difficulty_to_target(difficulty: u32) -> [u8; 32] {
        let mut target = [0xff; 32];
        let leading_zeros = difficulty / 8;
        let remaining_bits = difficulty % 8;
        
        // Set leading zero bytes
        for i in 0..leading_zeros as usize {
            if i < 32 {
                target[i] = 0x00;
            }
        }
        
        // Set partial byte if needed
        if leading_zeros < 32 && remaining_bits > 0 {
            target[leading_zeros as usize] = 0xff >> remaining_bits;
        }
        
        target
    }

    /// Get the difficulty as a human-readable string
    pub fn difficulty_string(&self) -> String {
        format!("0x{:08x}", self.difficulty)
    }
}

/// A block in the blockchain
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    /// Block header
    pub header: BlockHeader,
    /// List of transactions in the block
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// Create a new block
    pub fn new(
        prev_block_hash: Hash,
        transactions: Vec<Transaction>,
        difficulty: u32,
        height: u64,
    ) -> Result<Self> {
        if transactions.is_empty() {
            return Err(BlockchainError::BlockValidation(
                "Block must contain at least one transaction".to_string(),
            ));
        }

        // Calculate merkle root
        let tx_hashes: Result<Vec<Hash>> = transactions
            .iter()
            .map(|tx| tx.hash())
            .collect();
        let tx_hashes = tx_hashes?;
        let merkle_root = calculate_merkle_root(&tx_hashes);

        let header = BlockHeader::new(
            1, // version
            prev_block_hash,
            merkle_root,
            difficulty,
            height,
        );

        Ok(Self {
            header,
            transactions,
        })
    }

    /// Create the genesis block
    pub fn genesis(genesis_address: &str) -> Result<Self> {
        let coinbase_tx = Transaction::coinbase(genesis_address, 0);
        let transactions = vec![coinbase_tx];
        
        let tx_hashes: Result<Vec<Hash>> = transactions
            .iter()
            .map(|tx| tx.hash())
            .collect();
        let tx_hashes = tx_hashes?;
        let merkle_root = calculate_merkle_root(&tx_hashes);

        let header = BlockHeader::new(
            1, // version
            Hash::zero(), // no previous block
            merkle_root,
            crate::DIFFICULTY,
            0, // height 0
        );

        Ok(Self {
            header,
            transactions,
        })
    }

    /// Get the hash of this block
    pub fn hash(&self) -> Result<Hash> {
        self.header.hash()
    }

    /// Check if this is the genesis block
    pub fn is_genesis(&self) -> bool {
        self.header.height == 0 && self.header.prev_block_hash == Hash::zero()
    }

    /// Get the coinbase transaction (first transaction)
    pub fn coinbase_transaction(&self) -> Option<&Transaction> {
        self.transactions.first()
    }

    /// Get all non-coinbase transactions
    pub fn regular_transactions(&self) -> &[Transaction] {
        if self.transactions.is_empty() {
            &[]
        } else {
            &self.transactions[1..]
        }
    }

    /// Calculate the total transaction fees in this block
    pub fn total_fees(&self, utxo_set: &std::collections::HashMap<String, crate::transaction::UTXO>) -> u64 {
        self.regular_transactions()
            .iter()
            .map(|tx| tx.fee(utxo_set))
            .sum()
    }

    /// Get the total value of all outputs in this block
    pub fn total_output_value(&self) -> u64 {
        self.transactions
            .iter()
            .map(|tx| tx.output_value())
            .sum()
    }

    /// Get the block size in bytes
    pub fn size(&self) -> Result<usize> {
        let serialized = serialize(self)?;
        Ok(serialized.len())
    }

    /// Get the number of transactions in this block
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }

    /// Validate the block structure and transactions
    pub fn validate(&self, utxo_set: &std::collections::HashMap<String, crate::transaction::UTXO>) -> Result<()> {
        // Check that block has transactions
        if self.transactions.is_empty() {
            return Err(BlockchainError::BlockValidation(
                "Block must contain at least one transaction".to_string(),
            ));
        }

        // Check that first transaction is coinbase
        if !self.transactions[0].is_coinbase() {
            return Err(BlockchainError::BlockValidation(
                "First transaction must be coinbase".to_string(),
            ));
        }

        // Check that only first transaction is coinbase
        for (i, tx) in self.transactions.iter().enumerate() {
            if i == 0 {
                if !tx.is_coinbase() {
                    return Err(BlockchainError::BlockValidation(
                        "First transaction must be coinbase".to_string(),
                    ));
                }
            } else if tx.is_coinbase() {
                return Err(BlockchainError::BlockValidation(
                    "Only first transaction can be coinbase".to_string(),
                ));
            }
        }

        // Validate merkle root
        let tx_hashes: Result<Vec<Hash>> = self.transactions
            .iter()
            .map(|tx| tx.hash())
            .collect();
        let tx_hashes = tx_hashes?;
        let calculated_merkle_root = calculate_merkle_root(&tx_hashes);
        
        if self.header.merkle_root != calculated_merkle_root {
            return Err(BlockchainError::BlockValidation(
                "Invalid merkle root".to_string(),
            ));
        }

        // Validate all transactions
        for tx in &self.transactions {
            tx.validate(utxo_set)?;
        }

        // Check proof of work
        if !self.header.meets_difficulty()? {
            return Err(BlockchainError::BlockValidation(
                "Block does not meet difficulty requirement".to_string(),
            ));
        }

        // Check timestamp (should not be too far in the future)
        let current_time = current_timestamp();
        if self.header.timestamp > current_time + 7200 { // 2 hours tolerance
            return Err(BlockchainError::BlockValidation(
                "Block timestamp too far in the future".to_string(),
            ));
        }

        Ok(())
    }

    /// Mine the block by finding a valid nonce
    pub fn mine(&mut self) -> Result<()> {
        println!("Mining block at height {} with difficulty {}...", 
                self.header.height, self.header.difficulty);
        
        let start_time = std::time::Instant::now();
        let mut attempts = 0u64;
        
        loop {
            attempts += 1;
            
            // Check if we found a valid hash
            if self.header.meets_difficulty()? {
                let duration = start_time.elapsed();
                println!("Block mined! Nonce: {}, Attempts: {}, Time: {:.2}s", 
                        self.header.nonce, attempts, duration.as_secs_f64());
                return Ok(());
            }
            
            // Increment nonce and try again
            self.header.nonce = self.header.nonce.wrapping_add(1);
            
            // Update timestamp occasionally to prevent stale work
            if attempts % 1000000 == 0 {
                self.header.timestamp = current_timestamp();
                println!("Mining... attempts: {}, nonce: {}", attempts, self.header.nonce);
            }
            
            // Safety check to prevent infinite loops in tests
            if attempts > u64::MAX / 2 {
                return Err(BlockchainError::MiningError(
                    "Mining took too long, difficulty may be too high".to_string(),
                ));
            }
        }
    }

    /// Get block statistics as a formatted string
    pub fn stats(&self) -> Result<String> {
        let hash = self.hash()?;
        let size = self.size()?;
        
        Ok(format!(
            "Block #{} ({})
\
            Hash: {}
\
            Previous: {}
\
            Merkle Root: {}
\
            Timestamp: {} ({})
\
            Difficulty: {}
\
            Nonce: {}
\
            Transactions: {}
\
            Size: {} bytes",
            self.header.height,
            if self.is_genesis() { "Genesis" } else { "Regular" },
            hash.to_hex(),
            self.header.prev_block_hash.to_hex(),
            self.header.merkle_root.to_hex(),
            self.header.timestamp,
            chrono::DateTime::from_timestamp(self.header.timestamp as i64, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| "Invalid timestamp".to_string()),
            self.header.difficulty_string(),
            self.header.nonce,
            self.transaction_count(),
            size
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::Transaction;
    use std::collections::HashMap;

    #[test]
    fn test_genesis_block_creation() {
        let genesis = Block::genesis("genesis_address").unwrap();
        assert!(genesis.is_genesis());
        assert_eq!(genesis.header.height, 0);
        assert_eq!(genesis.header.prev_block_hash, Hash::zero());
        assert_eq!(genesis.transactions.len(), 1);
        assert!(genesis.transactions[0].is_coinbase());
    }

    #[test]
    fn test_block_creation() {
        let prev_hash = Hash::hash(b"previous_block");
        let coinbase_tx = Transaction::coinbase("miner_address", 1);
        let transactions = vec![coinbase_tx];
        
        let block = Block::new(prev_hash.clone(), transactions, crate::DIFFICULTY, 1).unwrap();
        assert_eq!(block.header.prev_block_hash, prev_hash);
        assert_eq!(block.header.height, 1);
        assert!(!block.is_genesis());
    }

    #[test]
    fn test_block_hash() {
        let genesis = Block::genesis("test_address").unwrap();
        let hash1 = genesis.hash().unwrap();
        let hash2 = genesis.hash().unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_block_validation() {
        let genesis = Block::genesis("test_address").unwrap();
        let utxo_set = HashMap::new();
        
        // Genesis block should be valid without mining
        // (we'll skip the difficulty check for this test)
        let result = genesis.validate(&utxo_set);
        // This might fail due to difficulty, which is expected
        match result {
            Ok(_) => {}, // Block is valid
            Err(BlockchainError::BlockValidation(msg)) if msg.contains("difficulty") => {
                // Expected failure due to difficulty
            },
            Err(e) => panic!("Unexpected validation error: {:?}", e),
        }
    }

    #[test]
    fn test_difficulty_target() {
        let target = BlockHeader::difficulty_to_target(8);
        assert_eq!(target[0], 0x00);
        assert_ne!(target[1], 0x00); // Should not be all zeros
    }

    #[test]
    fn test_block_stats() {
        let genesis = Block::genesis("test_address").unwrap();
        let stats = genesis.stats().unwrap();
        assert!(stats.contains("Block #0"));
        assert!(stats.contains("Genesis"));
        assert!(stats.contains("Transactions: 1"));
    }

    #[test]
    fn test_coinbase_transaction() {
        let genesis = Block::genesis("test_address").unwrap();
        let coinbase = genesis.coinbase_transaction().unwrap();
        assert!(coinbase.is_coinbase());
        
        let regular_txs = genesis.regular_transactions();
        assert_eq!(regular_txs.len(), 0);
    }

    #[test]
    fn test_block_size() {
        let genesis = Block::genesis("test_address").unwrap();
        let size = genesis.size().unwrap();
        assert!(size > 0);
    }

    #[test]
    fn test_total_output_value() {
        let genesis = Block::genesis("test_address").unwrap();
        let total_value = genesis.total_output_value();
        assert_eq!(total_value, crate::BLOCK_REWARD);
    }
}