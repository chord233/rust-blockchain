//! Memory pool implementation for pending transactions

use crate::crypto::Hash;
use crate::error::{BlockchainError, Result};
use crate::transaction::{Transaction, UTXO};
use std::collections::{HashMap, BTreeSet};
use std::sync::{Arc, RwLock};
use tracing::{info, warn, debug};

/// Transaction with priority information
#[derive(Debug, Clone)]
pub struct PendingTransaction {
    /// The transaction
    pub transaction: Transaction,
    /// Transaction hash
    pub hash: Hash,
    /// Priority score for ordering
    pub priority: f64,
    /// Fee per byte
    pub fee_per_byte: f64,
    /// Timestamp when added to mempool
    pub added_at: u64,
    /// Size in bytes
    pub size: usize,
}

impl PendingTransaction {
    /// Create a new pending transaction
    pub fn new(
        transaction: Transaction,
        utxo_set: &HashMap<String, UTXO>,
        current_height: u64,
    ) -> Result<Self> {
        let hash = transaction.hash()?;
        let priority = transaction.priority(utxo_set, current_height);
        let size = transaction.size()?;
        let fee = transaction.fee(utxo_set);
        let fee_per_byte = if size > 0 { fee as f64 / size as f64 } else { 0.0 };
        
        Ok(Self {
            transaction,
            hash,
            priority,
            fee_per_byte,
            added_at: crate::utils::current_timestamp(),
            size,
        })
    }

    /// Get the transaction fee
    pub fn fee(&self, utxo_set: &HashMap<String, UTXO>) -> u64 {
        self.transaction.fee(utxo_set)
    }

    /// Check if transaction is expired (older than max_age seconds)
    pub fn is_expired(&self, max_age: u64) -> bool {
        let current_time = crate::utils::current_timestamp();
        current_time.saturating_sub(self.added_at) > max_age
    }
}

/// Ordering for pending transactions (higher priority first)
impl PartialEq for PendingTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl Eq for PendingTransaction {}

impl PartialOrd for PendingTransaction {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PendingTransaction {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // First compare by fee per byte (higher is better)
        match other.fee_per_byte.partial_cmp(&self.fee_per_byte) {
            Some(std::cmp::Ordering::Equal) => {
                // Then by priority (higher is better)
                match other.priority.partial_cmp(&self.priority) {
                    Some(std::cmp::Ordering::Equal) => {
                        // Finally by timestamp (older first)
                        self.added_at.cmp(&other.added_at)
                    }
                    Some(ord) => ord,
                    None => std::cmp::Ordering::Equal,
                }
            }
            Some(ord) => ord,
            None => std::cmp::Ordering::Equal,
        }
    }
}

/// Memory pool configuration
#[derive(Debug, Clone)]
pub struct MempoolConfig {
    /// Maximum number of transactions in mempool
    pub max_transactions: usize,
    /// Maximum mempool size in bytes
    pub max_size_bytes: usize,
    /// Maximum transaction age in seconds
    pub max_transaction_age: u64,
    /// Minimum fee per byte to accept
    pub min_fee_per_byte: f64,
    /// Maximum transaction size in bytes
    pub max_transaction_size: usize,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_transactions: 10000,
            max_size_bytes: 100 * 1024 * 1024, // 100 MB
            max_transaction_age: 24 * 60 * 60, // 24 hours
            min_fee_per_byte: 1.0, // 1 satoshi per byte
            max_transaction_size: 100 * 1024, // 100 KB
        }
    }
}

/// Memory pool for pending transactions
#[derive(Debug)]
pub struct Mempool {
    /// Configuration
    config: MempoolConfig,
    /// Pending transactions ordered by priority
    transactions: Arc<RwLock<BTreeSet<PendingTransaction>>>,
    /// Transaction hash to pending transaction mapping
    tx_map: Arc<RwLock<HashMap<Hash, PendingTransaction>>>,
    /// Current total size in bytes
    total_size: Arc<RwLock<usize>>,
}

impl Mempool {
    /// Create a new mempool
    pub fn new(config: MempoolConfig) -> Self {
        Self {
            config,
            transactions: Arc::new(RwLock::new(BTreeSet::new())),
            tx_map: Arc::new(RwLock::new(HashMap::new())),
            total_size: Arc::new(RwLock::new(0)),
        }
    }

    /// Create a mempool with default configuration
    pub fn default() -> Self {
        Self::new(MempoolConfig::default())
    }

    /// Add a transaction to the mempool
    pub fn add_transaction(
        &self,
        transaction: Transaction,
        utxo_set: &HashMap<String, UTXO>,
        current_height: u64,
    ) -> Result<()> {
        // Validate transaction first
        transaction.validate(utxo_set)?;
        
        let pending_tx = PendingTransaction::new(transaction, utxo_set, current_height)?;
        
        // Check transaction size
        if pending_tx.size > self.config.max_transaction_size {
            return Err(BlockchainError::TransactionValidation(
                format!("Transaction too large: {} bytes", pending_tx.size)
            ));
        }
        
        // Check minimum fee
        if pending_tx.fee_per_byte < self.config.min_fee_per_byte {
            return Err(BlockchainError::TransactionValidation(
                format!("Fee too low: {:.2} sat/byte", pending_tx.fee_per_byte)
            ));
        }
        
        // Check for double spending
        if self.has_conflicting_transaction(&pending_tx)? {
            return Err(BlockchainError::TransactionValidation(
                "Transaction conflicts with existing mempool transaction".to_string()
            ));
        }
        
        let tx_hash = pending_tx.hash.clone();
        
        // Check if transaction already exists
        {
            let tx_map = self.tx_map.read().unwrap();
            if tx_map.contains_key(&tx_hash) {
                return Err(BlockchainError::TransactionValidation(
                    "Transaction already in mempool".to_string()
                ));
            }
        }
        
        // Make room if necessary
        self.make_room_if_needed(pending_tx.size)?;
        
        // Add transaction
        {
            let mut transactions = self.transactions.write().unwrap();
            let mut tx_map = self.tx_map.write().unwrap();
            let mut total_size = self.total_size.write().unwrap();
            
            transactions.insert(pending_tx.clone());
            tx_map.insert(tx_hash.clone(), pending_tx);
            *total_size += pending_tx.size;
        }
        
        info!("Added transaction {} to mempool", tx_hash.to_hex());
        Ok(())
    }

    /// Remove a transaction from the mempool
    pub fn remove_transaction(&self, tx_hash: &Hash) -> Option<PendingTransaction> {
        let mut transactions = self.transactions.write().unwrap();
        let mut tx_map = self.tx_map.write().unwrap();
        let mut total_size = self.total_size.write().unwrap();
        
        if let Some(pending_tx) = tx_map.remove(tx_hash) {
            transactions.remove(&pending_tx);
            *total_size = total_size.saturating_sub(pending_tx.size);
            debug!("Removed transaction {} from mempool", tx_hash.to_hex());
            Some(pending_tx)
        } else {
            None
        }
    }

    /// Get transactions for mining (highest priority first)
    pub fn get_transactions_for_mining(
        &self,
        max_count: usize,
        max_size: usize,
        utxo_set: &HashMap<String, UTXO>,
    ) -> Vec<Transaction> {
        let transactions = self.transactions.read().unwrap();
        let mut selected = Vec::new();
        let mut total_size = 0;
        let mut used_utxos = std::collections::HashSet::new();
        
        for pending_tx in transactions.iter() {
            if selected.len() >= max_count || total_size + pending_tx.size > max_size {
                break;
            }
            
            // Check for conflicts with already selected transactions
            let mut conflicts = false;
            if !pending_tx.transaction.is_coinbase() {
                for input in &pending_tx.transaction.inputs {
                    let utxo_id = format!("{}:{}", input.prev_tx_hash.to_hex(), input.output_index);
                    if used_utxos.contains(&utxo_id) {
                        conflicts = true;
                        break;
                    }
                }
            }
            
            if !conflicts {
                // Mark UTXOs as used
                if !pending_tx.transaction.is_coinbase() {
                    for input in &pending_tx.transaction.inputs {
                        let utxo_id = format!("{}:{}", input.prev_tx_hash.to_hex(), input.output_index);
                        used_utxos.insert(utxo_id);
                    }
                }
                
                selected.push(pending_tx.transaction.clone());
                total_size += pending_tx.size;
            }
        }
        
        debug!("Selected {} transactions for mining ({} bytes)", selected.len(), total_size);
        selected
    }

    /// Remove transactions that are included in a block
    pub fn remove_transactions(&self, transactions: &[Transaction]) -> Result<()> {
        for tx in transactions {
            let tx_hash = tx.hash()?;
            self.remove_transaction(&tx_hash);
        }
        Ok(())
    }

    /// Clean up expired transactions
    pub fn cleanup_expired(&self) -> usize {
        let mut transactions = self.transactions.write().unwrap();
        let mut tx_map = self.tx_map.write().unwrap();
        let mut total_size = self.total_size.write().unwrap();
        
        let expired: Vec<_> = transactions
            .iter()
            .filter(|tx| tx.is_expired(self.config.max_transaction_age))
            .cloned()
            .collect();
        
        let mut removed_size = 0;
        for expired_tx in &expired {
            transactions.remove(expired_tx);
            tx_map.remove(&expired_tx.hash);
            removed_size += expired_tx.size;
        }
        
        *total_size = total_size.saturating_sub(removed_size);
        
        if !expired.is_empty() {
            info!("Cleaned up {} expired transactions", expired.len());
        }
        
        expired.len()
    }

    /// Make room for a new transaction by removing lowest priority ones
    fn make_room_if_needed(&self, new_tx_size: usize) -> Result<()> {
        let current_count = self.tx_map.read().unwrap().len();
        let current_size = *self.total_size.read().unwrap();
        
        // Check if we need to make room
        let needs_room = current_count >= self.config.max_transactions
            || current_size + new_tx_size > self.config.max_size_bytes;
        
        if !needs_room {
            return Ok(());
        }
        
        let mut transactions = self.transactions.write().unwrap();
        let mut tx_map = self.tx_map.write().unwrap();
        let mut total_size = self.total_size.write().unwrap();
        
        // Remove lowest priority transactions
        let mut removed_count = 0;
        let mut removed_size = 0;
        
        while (transactions.len() >= self.config.max_transactions
            || *total_size + new_tx_size > self.config.max_size_bytes)
            && !transactions.is_empty()
        {
            // Remove the lowest priority transaction (last in the set)
            if let Some(lowest_priority) = transactions.iter().next_back().cloned() {
                transactions.remove(&lowest_priority);
                tx_map.remove(&lowest_priority.hash);
                removed_size += lowest_priority.size;
                removed_count += 1;
            } else {
                break;
            }
        }
        
        *total_size = total_size.saturating_sub(removed_size);
        
        if removed_count > 0 {
            warn!("Removed {} low-priority transactions to make room", removed_count);
        }
        
        Ok(())
    }

    /// Check if a transaction conflicts with existing mempool transactions
    fn has_conflicting_transaction(&self, pending_tx: &PendingTransaction) -> Result<bool> {
        if pending_tx.transaction.is_coinbase() {
            return Ok(false); // Coinbase transactions don't conflict
        }
        
        let tx_map = self.tx_map.read().unwrap();
        
        for input in &pending_tx.transaction.inputs {
            let utxo_id = format!("{}:{}", input.prev_tx_hash.to_hex(), input.output_index);
            
            // Check if any existing transaction uses the same UTXO
            for existing_tx in tx_map.values() {
                if !existing_tx.transaction.is_coinbase() {
                    for existing_input in &existing_tx.transaction.inputs {
                        let existing_utxo_id = format!(
                            "{}:{}",
                            existing_input.prev_tx_hash.to_hex(),
                            existing_input.output_index
                        );
                        if utxo_id == existing_utxo_id {
                            return Ok(true); // Conflict found
                        }
                    }
                }
            }
        }
        
        Ok(false)
    }

    /// Get mempool statistics
    pub fn get_stats(&self) -> MempoolStats {
        let transactions = self.transactions.read().unwrap();
        let total_size = *self.total_size.read().unwrap();
        
        let transaction_count = transactions.len();
        let total_fees: u64 = transactions
            .iter()
            .map(|tx| tx.transaction.fee(&HashMap::new())) // Note: This won't be accurate without UTXO set
            .sum();
        
        let average_fee_per_byte = if transaction_count > 0 && total_size > 0 {
            total_fees as f64 / total_size as f64
        } else {
            0.0
        };
        
        MempoolStats {
            transaction_count,
            total_size,
            total_fees,
            average_fee_per_byte,
            max_transactions: self.config.max_transactions,
            max_size_bytes: self.config.max_size_bytes,
        }
    }

    /// Get a transaction by hash
    pub fn get_transaction(&self, tx_hash: &Hash) -> Option<Transaction> {
        let tx_map = self.tx_map.read().unwrap();
        tx_map.get(tx_hash).map(|pending_tx| pending_tx.transaction.clone())
    }

    /// Check if mempool contains a transaction
    pub fn contains_transaction(&self, tx_hash: &Hash) -> bool {
        let tx_map = self.tx_map.read().unwrap();
        tx_map.contains_key(tx_hash)
    }

    /// Get all transaction hashes in the mempool
    pub fn get_all_transaction_hashes(&self) -> Vec<Hash> {
        let tx_map = self.tx_map.read().unwrap();
        tx_map.keys().cloned().collect()
    }

    /// Clear all transactions from the mempool
    pub fn clear(&self) {
        let mut transactions = self.transactions.write().unwrap();
        let mut tx_map = self.tx_map.write().unwrap();
        let mut total_size = self.total_size.write().unwrap();
        
        transactions.clear();
        tx_map.clear();
        *total_size = 0;
        
        info!("Cleared all transactions from mempool");
    }
}

/// Mempool statistics
#[derive(Debug, Clone)]
pub struct MempoolStats {
    /// Number of transactions in mempool
    pub transaction_count: usize,
    /// Total size in bytes
    pub total_size: usize,
    /// Total fees of all transactions
    pub total_fees: u64,
    /// Average fee per byte
    pub average_fee_per_byte: f64,
    /// Maximum allowed transactions
    pub max_transactions: usize,
    /// Maximum allowed size in bytes
    pub max_size_bytes: usize,
}

impl MempoolStats {
    /// Format stats as a string
    pub fn format(&self) -> String {
        format!(
            "Mempool Statistics:\n\
            Transactions: {} / {}\n\
            Size: {} / {} bytes ({:.1}% full)\n\
            Total Fees: {} satoshis\n\
            Average Fee: {:.2} sat/byte",
            self.transaction_count,
            self.max_transactions,
            self.total_size,
            self.max_size_bytes,
            (self.total_size as f64 / self.max_size_bytes as f64) * 100.0,
            self.total_fees,
            self.average_fee_per_byte
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{Transaction, TxInput, TxOutput};
    use crate::crypto::Hash;
    use std::collections::HashMap;

    fn create_test_transaction() -> Transaction {
        let input = TxInput::new(Hash::hash(b"prev_tx"), 0);
        let output = TxOutput::new(100, "test_address".to_string());
        Transaction::new(vec![input], vec![output])
    }

    #[test]
    fn test_mempool_creation() {
        let mempool = Mempool::default();
        let stats = mempool.get_stats();
        assert_eq!(stats.transaction_count, 0);
        assert_eq!(stats.total_size, 0);
    }

    #[test]
    fn test_pending_transaction_creation() {
        let tx = create_test_transaction();
        let utxo_set = HashMap::new();
        let pending_tx = PendingTransaction::new(tx, &utxo_set, 100).unwrap();
        
        assert!(pending_tx.size > 0);
        assert!(pending_tx.added_at > 0);
    }

    #[test]
    fn test_pending_transaction_ordering() {
        let tx1 = create_test_transaction();
        let tx2 = create_test_transaction();
        let utxo_set = HashMap::new();
        
        let mut pending_tx1 = PendingTransaction::new(tx1, &utxo_set, 100).unwrap();
        let mut pending_tx2 = PendingTransaction::new(tx2, &utxo_set, 100).unwrap();
        
        // Set different fee rates
        pending_tx1.fee_per_byte = 10.0;
        pending_tx2.fee_per_byte = 5.0;
        
        // Higher fee should come first
        assert!(pending_tx1 < pending_tx2);
    }

    #[test]
    fn test_mempool_stats() {
        let mempool = Mempool::default();
        let stats = mempool.get_stats();
        
        assert_eq!(stats.transaction_count, 0);
        assert_eq!(stats.total_fees, 0);
        assert_eq!(stats.average_fee_per_byte, 0.0);
    }

    #[test]
    fn test_mempool_clear() {
        let mempool = Mempool::default();
        mempool.clear();
        
        let stats = mempool.get_stats();
        assert_eq!(stats.transaction_count, 0);
    }

    #[test]
    fn test_transaction_expiry() {
        let tx = create_test_transaction();
        let utxo_set = HashMap::new();
        let mut pending_tx = PendingTransaction::new(tx, &utxo_set, 100).unwrap();
        
        // Set old timestamp
        pending_tx.added_at = 0;
        
        assert!(pending_tx.is_expired(1000));
        assert!(!pending_tx.is_expired(u64::MAX));
    }

    #[test]
    fn test_mempool_config_default() {
        let config = MempoolConfig::default();
        assert!(config.max_transactions > 0);
        assert!(config.max_size_bytes > 0);
        assert!(config.max_transaction_age > 0);
    }
}