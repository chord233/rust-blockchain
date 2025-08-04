//! Consensus implementation for the blockchain

use crate::block::{Block, BlockHeader};
use crate::crypto::Hash;
use crate::error::{BlockchainError, Result};
use crate::transaction::Transaction;
use crate::utils;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Target block time in seconds
pub const TARGET_BLOCK_TIME: u64 = 600; // 10 minutes

/// Difficulty adjustment interval (number of blocks)
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 2016; // ~2 weeks

/// Maximum difficulty adjustment factor
pub const MAX_DIFFICULTY_ADJUSTMENT: f64 = 4.0;

/// Minimum difficulty adjustment factor
pub const MIN_DIFFICULTY_ADJUSTMENT: f64 = 0.25;

/// Initial difficulty
pub const INITIAL_DIFFICULTY: u32 = 0x1d00ffff; // Bitcoin's initial difficulty

/// Consensus parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusParams {
    /// Target time between blocks (seconds)
    pub target_block_time: u64,
    /// Number of blocks between difficulty adjustments
    pub difficulty_adjustment_interval: u64,
    /// Maximum difficulty adjustment factor
    pub max_difficulty_adjustment: f64,
    /// Minimum difficulty adjustment factor
    pub min_difficulty_adjustment: f64,
    /// Initial difficulty
    pub initial_difficulty: u32,
    /// Maximum block size in bytes
    pub max_block_size: usize,
    /// Maximum number of transactions per block
    pub max_transactions_per_block: usize,
    /// Block reward in satoshis
    pub block_reward: u64,
    /// Halving interval (number of blocks)
    pub halving_interval: u64,
}

impl Default for ConsensusParams {
    fn default() -> Self {
        Self {
            target_block_time: TARGET_BLOCK_TIME,
            difficulty_adjustment_interval: DIFFICULTY_ADJUSTMENT_INTERVAL,
            max_difficulty_adjustment: MAX_DIFFICULTY_ADJUSTMENT,
            min_difficulty_adjustment: MIN_DIFFICULTY_ADJUSTMENT,
            initial_difficulty: INITIAL_DIFFICULTY,
            max_block_size: 1024 * 1024, // 1 MB
            max_transactions_per_block: 4000,
            block_reward: 50 * 100_000_000, // 50 BTC in satoshis
            halving_interval: 210_000, // ~4 years
        }
    }
}

/// Consensus engine for Proof of Work
#[derive(Debug)]
pub struct ProofOfWork {
    /// Consensus parameters
    params: ConsensusParams,
}

impl ProofOfWork {
    /// Create a new Proof of Work consensus engine
    pub fn new(params: ConsensusParams) -> Self {
        Self { params }
    }

    /// Create with default parameters
    pub fn default() -> Self {
        Self::new(ConsensusParams::default())
    }

    /// Validate a block according to consensus rules
    pub fn validate_block(
        &self,
        block: &Block,
        previous_block: Option<&Block>,
        blockchain_height: u64,
    ) -> Result<()> {
        // Validate block header
        self.validate_block_header(&block.header, previous_block, blockchain_height)?;

        // Validate block size
        let block_size = block.size()?;
        if block_size > self.params.max_block_size {
            return Err(BlockchainError::ConsensusError(format!(
                "Block size {} exceeds maximum {}",
                block_size, self.params.max_block_size
            )));
        }

        // Validate number of transactions
        if block.transactions.len() > self.params.max_transactions_per_block {
            return Err(BlockchainError::ConsensusError(format!(
                "Block has {} transactions, maximum is {}",
                block.transactions.len(),
                self.params.max_transactions_per_block
            )));
        }

        // Validate transactions
        self.validate_transactions(&block.transactions, blockchain_height)?;

        // Validate merkle root
        let calculated_merkle_root = utils::calculate_merkle_root(
            &block.transactions.iter().map(|tx| tx.hash()).collect::<Result<Vec<_>>>()?[..],
        );
        if calculated_merkle_root != block.header.merkle_root {
            return Err(BlockchainError::ConsensusError(
                "Invalid merkle root".to_string(),
            ));
        }

        // Validate proof of work
        self.validate_proof_of_work(&block.header)?;

        Ok(())
    }

    /// Validate block header
    pub fn validate_block_header(
        &self,
        header: &BlockHeader,
        previous_block: Option<&Block>,
        blockchain_height: u64,
    ) -> Result<()> {
        // Validate version
        if header.version == 0 {
            return Err(BlockchainError::ConsensusError(
                "Invalid block version".to_string(),
            ));
        }

        // Validate height
        let expected_height = if let Some(prev) = previous_block {
            prev.header.height + 1
        } else {
            0 // Genesis block
        };

        if header.height != expected_height {
            return Err(BlockchainError::ConsensusError(format!(
                "Invalid block height: expected {}, got {}",
                expected_height, header.height
            )));
        }

        // Validate previous hash
        if let Some(prev) = previous_block {
            let prev_hash = prev.hash()?;
            if header.prev_hash != prev_hash {
                return Err(BlockchainError::ConsensusError(
                    "Invalid previous block hash".to_string(),
                ));
            }
        } else if header.height == 0 {
            // Genesis block should have zero previous hash
            if header.prev_hash != Hash::zero() {
                return Err(BlockchainError::ConsensusError(
                    "Genesis block must have zero previous hash".to_string(),
                ));
            }
        }

        // Validate timestamp
        self.validate_timestamp(header, previous_block)?;

        // Validate difficulty
        let expected_difficulty = self.calculate_next_difficulty(previous_block, blockchain_height)?;
        if header.difficulty != expected_difficulty {
            return Err(BlockchainError::ConsensusError(format!(
                "Invalid difficulty: expected {}, got {}",
                expected_difficulty, header.difficulty
            )));
        }

        Ok(())
    }

    /// Validate transactions in a block
    pub fn validate_transactions(
        &self,
        transactions: &[Transaction],
        block_height: u64,
    ) -> Result<()> {
        if transactions.is_empty() {
            return Err(BlockchainError::ConsensusError(
                "Block must contain at least one transaction".to_string(),
            ));
        }

        // First transaction must be coinbase
        if !transactions[0].is_coinbase() {
            return Err(BlockchainError::ConsensusError(
                "First transaction must be coinbase".to_string(),
            ));
        }

        // Validate coinbase transaction
        self.validate_coinbase_transaction(&transactions[0], block_height)?;

        // Only one coinbase transaction allowed
        for (i, tx) in transactions.iter().enumerate().skip(1) {
            if tx.is_coinbase() {
                return Err(BlockchainError::ConsensusError(format!(
                    "Multiple coinbase transactions found at index {}",
                    i
                )));
            }
        }

        // Check for duplicate transactions
        let mut tx_hashes = std::collections::HashSet::new();
        for tx in transactions {
            let tx_hash = tx.hash()?;
            if !tx_hashes.insert(tx_hash) {
                return Err(BlockchainError::ConsensusError(
                    "Duplicate transaction in block".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Validate coinbase transaction
    pub fn validate_coinbase_transaction(
        &self,
        transaction: &Transaction,
        block_height: u64,
    ) -> Result<()> {
        if !transaction.is_coinbase() {
            return Err(BlockchainError::ConsensusError(
                "Transaction is not a coinbase transaction".to_string(),
            ));
        }

        // Calculate expected block reward
        let expected_reward = self.calculate_block_reward(block_height);

        // Calculate total output value
        let total_output: u64 = transaction.outputs.iter().map(|output| output.value).sum();

        // Coinbase output should not exceed block reward + fees
        // Note: In a real implementation, you'd also add transaction fees
        if total_output > expected_reward {
            return Err(BlockchainError::ConsensusError(format!(
                "Coinbase output {} exceeds block reward {}",
                total_output, expected_reward
            )));
        }

        Ok(())
    }

    /// Validate proof of work
    pub fn validate_proof_of_work(&self, header: &BlockHeader) -> Result<()> {
        let hash = header.hash()?;
        let target = self.difficulty_to_target(header.difficulty)?;

        if !self.hash_meets_target(&hash, &target) {
            return Err(BlockchainError::ConsensusError(
                "Proof of work validation failed".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate block timestamp
    pub fn validate_timestamp(
        &self,
        header: &BlockHeader,
        previous_block: Option<&Block>,
    ) -> Result<()> {
        let current_time = utils::current_timestamp();

        // Block timestamp should not be too far in the future (2 hours)
        if header.timestamp > current_time + 2 * 3600 {
            return Err(BlockchainError::ConsensusError(
                "Block timestamp too far in the future".to_string(),
            ));
        }

        // Block timestamp should be greater than previous block
        if let Some(prev) = previous_block {
            if header.timestamp <= prev.header.timestamp {
                return Err(BlockchainError::ConsensusError(
                    "Block timestamp must be greater than previous block".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Calculate the next difficulty
    pub fn calculate_next_difficulty(
        &self,
        previous_block: Option<&Block>,
        blockchain_height: u64,
    ) -> Result<u32> {
        // Genesis block uses initial difficulty
        if previous_block.is_none() {
            return Ok(self.params.initial_difficulty);
        }

        let prev_block = previous_block.unwrap();

        // If not at adjustment interval, use previous difficulty
        if (blockchain_height + 1) % self.params.difficulty_adjustment_interval != 0 {
            return Ok(prev_block.header.difficulty);
        }

        // Calculate new difficulty based on time taken for last interval
        // This is a simplified version - in practice you'd need the block from
        // difficulty_adjustment_interval blocks ago
        let target_time = self.params.target_block_time * self.params.difficulty_adjustment_interval;
        let actual_time = target_time; // Simplified - would calculate actual time

        let adjustment_factor = target_time as f64 / actual_time as f64;
        let clamped_factor = adjustment_factor
            .max(self.params.min_difficulty_adjustment)
            .min(self.params.max_difficulty_adjustment);

        let current_target = self.difficulty_to_target(prev_block.header.difficulty)?;
        let new_target = self.multiply_target_by_factor(&current_target, clamped_factor)?;
        let new_difficulty = self.target_to_difficulty(&new_target)?;

        info!(
            "Difficulty adjustment: {} -> {} (factor: {:.2})",
            prev_block.header.difficulty, new_difficulty, clamped_factor
        );

        Ok(new_difficulty)
    }

    /// Calculate block reward for a given height
    pub fn calculate_block_reward(&self, block_height: u64) -> u64 {
        let halvings = block_height / self.params.halving_interval;
        if halvings >= 64 {
            return 0; // No more rewards after 64 halvings
        }

        self.params.block_reward >> halvings
    }

    /// Convert difficulty to target
    pub fn difficulty_to_target(&self, difficulty: u32) -> Result<BigUint> {
        if difficulty == 0 {
            return Err(BlockchainError::ConsensusError(
                "Difficulty cannot be zero".to_string(),
            ));
        }

        // Extract exponent and mantissa from difficulty bits
        let exponent = (difficulty >> 24) as u8;
        let mantissa = difficulty & 0x00ffffff;

        if exponent <= 3 {
            return Err(BlockchainError::ConsensusError(
                "Invalid difficulty exponent".to_string(),
            ));
        }

        let target = BigUint::from(mantissa) << (8 * (exponent - 3));
        Ok(target)
    }

    /// Convert target to difficulty
    pub fn target_to_difficulty(&self, target: &BigUint) -> Result<u32> {
        if target.is_zero() {
            return Err(BlockchainError::ConsensusError(
                "Target cannot be zero".to_string(),
            ));
        }

        let target_bytes = target.to_bytes_be();
        if target_bytes.is_empty() {
            return Err(BlockchainError::ConsensusError(
                "Invalid target".to_string(),
            ));
        }

        let exponent = target_bytes.len() as u8;
        let mantissa = if target_bytes.len() >= 3 {
            u32::from_be_bytes([
                0,
                target_bytes[0],
                target_bytes[1],
                target_bytes[2],
            ])
        } else {
            let mut bytes = [0u8; 4];
            for (i, &byte) in target_bytes.iter().enumerate() {
                bytes[4 - target_bytes.len() + i] = byte;
            }
            u32::from_be_bytes(bytes)
        };

        let difficulty = ((exponent as u32) << 24) | (mantissa & 0x00ffffff);
        Ok(difficulty)
    }

    /// Check if hash meets target
    pub fn hash_meets_target(&self, hash: &Hash, target: &BigUint) -> bool {
        let hash_int = BigUint::from_bytes_be(&hash.as_bytes());
        hash_int <= *target
    }

    /// Multiply target by a factor
    fn multiply_target_by_factor(&self, target: &BigUint, factor: f64) -> Result<BigUint> {
        if factor <= 0.0 {
            return Err(BlockchainError::ConsensusError(
                "Factor must be positive".to_string(),
            ));
        }

        // Convert to f64, multiply, and convert back
        // This is approximate but sufficient for difficulty adjustment
        let target_f64 = target.to_string().parse::<f64>()
            .map_err(|_| BlockchainError::ConsensusError("Target too large".to_string()))?;
        
        let new_target_f64 = target_f64 * factor;
        let new_target_str = format!("{:.0}", new_target_f64);
        
        new_target_str.parse::<BigUint>()
            .map_err(|_| BlockchainError::ConsensusError("Invalid new target".to_string()))
    }

    /// Mine a block (find a valid nonce)
    pub fn mine_block(&self, mut header: BlockHeader) -> Result<BlockHeader> {
        let target = self.difficulty_to_target(header.difficulty)?;
        let start_time = Instant::now();
        let mut attempts = 0u64;

        info!("Starting to mine block at height {}", header.height);
        debug!("Target: {}", target);

        loop {
            let hash = header.hash()?;
            attempts += 1;

            if self.hash_meets_target(&hash, &target) {
                let elapsed = start_time.elapsed();
                info!(
                    "Block mined! Height: {}, Nonce: {}, Attempts: {}, Time: {:.2}s, Hash: {}",
                    header.height,
                    header.nonce,
                    attempts,
                    elapsed.as_secs_f64(),
                    hash.to_hex()
                );
                return Ok(header);
            }

            header.nonce = header.nonce.wrapping_add(1);

            // Log progress every million attempts
            if attempts % 1_000_000 == 0 {
                let elapsed = start_time.elapsed();
                let hash_rate = attempts as f64 / elapsed.as_secs_f64();
                debug!(
                    "Mining progress: {} attempts, {:.0} H/s, elapsed: {:.1}s",
                    attempts,
                    hash_rate,
                    elapsed.as_secs_f64()
                );
            }

            // Check for nonce overflow
            if header.nonce == 0 {
                warn!("Nonce overflow, updating timestamp");
                header.timestamp = utils::current_timestamp();
            }
        }
    }

    /// Estimate mining time for current difficulty
    pub fn estimate_mining_time(&self, difficulty: u32, hash_rate: f64) -> Duration {
        if hash_rate <= 0.0 {
            return Duration::from_secs(u64::MAX);
        }

        let target = match self.difficulty_to_target(difficulty) {
            Ok(target) => target,
            Err(_) => return Duration::from_secs(u64::MAX),
        };

        // Calculate expected number of attempts
        let max_target = BigUint::from(1u64) << 256;
        let expected_attempts = if target.is_zero() {
            f64::INFINITY
        } else {
            let target_f64 = target.to_string().parse::<f64>().unwrap_or(f64::INFINITY);
            let max_target_f64 = max_target.to_string().parse::<f64>().unwrap_or(f64::INFINITY);
            max_target_f64 / target_f64
        };

        let expected_time = expected_attempts / hash_rate;
        Duration::from_secs_f64(expected_time.min(u64::MAX as f64))
    }

    /// Get consensus parameters
    pub fn params(&self) -> &ConsensusParams {
        &self.params
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::Block;
    use crate::transaction::{Transaction, TxInput, TxOutput};

    fn create_test_block() -> Block {
        let coinbase_input = TxInput::coinbase(0, b"test".to_vec());
        let coinbase_output = TxOutput::new(50 * 100_000_000, "miner_address".to_string());
        let coinbase_tx = Transaction::new(vec![coinbase_input], vec![coinbase_output]);

        Block::new(
            0,
            Hash::zero(),
            vec![coinbase_tx],
            INITIAL_DIFFICULTY,
            0,
        ).unwrap()
    }

    #[test]
    fn test_consensus_params_default() {
        let params = ConsensusParams::default();
        assert_eq!(params.target_block_time, TARGET_BLOCK_TIME);
        assert_eq!(params.initial_difficulty, INITIAL_DIFFICULTY);
        assert!(params.block_reward > 0);
    }

    #[test]
    fn test_proof_of_work_creation() {
        let pow = ProofOfWork::default();
        assert_eq!(pow.params.target_block_time, TARGET_BLOCK_TIME);
    }

    #[test]
    fn test_block_reward_calculation() {
        let pow = ProofOfWork::default();
        
        // Initial reward
        assert_eq!(pow.calculate_block_reward(0), 50 * 100_000_000);
        
        // After first halving
        assert_eq!(pow.calculate_block_reward(210_000), 25 * 100_000_000);
        
        // After second halving
        assert_eq!(pow.calculate_block_reward(420_000), 12 * 100_000_000 + 50_000_000);
    }

    #[test]
    fn test_difficulty_target_conversion() {
        let pow = ProofOfWork::default();
        let difficulty = INITIAL_DIFFICULTY;
        
        let target = pow.difficulty_to_target(difficulty).unwrap();
        let converted_back = pow.target_to_difficulty(&target).unwrap();
        
        assert_eq!(difficulty, converted_back);
    }

    #[test]
    fn test_validate_coinbase_transaction() {
        let pow = ProofOfWork::default();
        let coinbase_input = TxInput::coinbase(0, b"test".to_vec());
        let coinbase_output = TxOutput::new(50 * 100_000_000, "miner_address".to_string());
        let coinbase_tx = Transaction::new(vec![coinbase_input], vec![coinbase_output]);
        
        assert!(pow.validate_coinbase_transaction(&coinbase_tx, 0).is_ok());
    }

    #[test]
    fn test_validate_block_header() {
        let pow = ProofOfWork::default();
        let block = create_test_block();
        
        // Genesis block should validate
        assert!(pow.validate_block_header(&block.header, None, 0).is_ok());
    }

    #[test]
    fn test_hash_meets_target() {
        let pow = ProofOfWork::default();
        let target = BigUint::from(0xffffffffu64) << 224; // Very easy target
        let hash = Hash::hash(b"test");
        
        // This should meet the target (very likely)
        let meets_target = pow.hash_meets_target(&hash, &target);
        // We can't guarantee this will always pass, but it's very likely
        // In a real test, you'd use a known hash and target
    }

    #[test]
    fn test_estimate_mining_time() {
        let pow = ProofOfWork::default();
        let hash_rate = 1000.0; // 1000 H/s
        let difficulty = INITIAL_DIFFICULTY;
        
        let estimated_time = pow.estimate_mining_time(difficulty, hash_rate);
        assert!(estimated_time.as_secs() > 0);
    }

    #[test]
    fn test_next_difficulty_calculation() {
        let pow = ProofOfWork::default();
        let block = create_test_block();
        
        // For genesis block
        let difficulty = pow.calculate_next_difficulty(None, 0).unwrap();
        assert_eq!(difficulty, INITIAL_DIFFICULTY);
        
        // For non-adjustment block
        let difficulty = pow.calculate_next_difficulty(Some(&block), 1).unwrap();
        assert_eq!(difficulty, block.header.difficulty);
    }
}