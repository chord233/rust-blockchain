//! # Rust Blockchain Library
//!
//! A comprehensive blockchain implementation in Rust featuring:
//! - Proof of Work consensus mechanism
//! - UTXO (Unspent Transaction Output) model
//! - P2P networking with libp2p
//! - Digital wallet functionality
//! - Mining capabilities
//! - Persistent storage

// Core modules
pub mod block;
pub mod blockchain;
pub mod transaction;
pub mod wallet;
pub mod mining;
pub mod network;
pub mod storage;
pub mod crypto;
pub mod consensus;
pub mod mempool;
pub mod utils;
pub mod error;

// Re-export commonly used types
pub use block::{Block, BlockHeader};
pub use blockchain::Blockchain;
pub use transaction::{Transaction, TxInput, TxOutput, UTXO};
pub use wallet::{Wallet, WalletManager};
pub use mining::{Miner, ProofOfWork};
pub use network::{NetworkNode, P2PNetwork};
pub use storage::{Storage, BlockchainDB};
pub use crypto::{KeyPair, Signature, Hash};
pub use consensus::{Consensus, ConsensusEngine};
pub use mempool::Mempool;
pub use error::{BlockchainError, Result};

// Constants
pub const DIFFICULTY: usize = 4;
pub const BLOCK_REWARD: u64 = 50;
pub const MAX_BLOCK_SIZE: usize = 1_000_000; // 1MB
pub const TARGET_BLOCK_TIME: u64 = 600; // 10 minutes in seconds
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 2016; // blocks

// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = env!("CARGO_PKG_NAME");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(DIFFICULTY, 4);
        assert_eq!(BLOCK_REWARD, 50);
        assert_eq!(MAX_BLOCK_SIZE, 1_000_000);
        assert_eq!(TARGET_BLOCK_TIME, 600);
        assert_eq!(DIFFICULTY_ADJUSTMENT_INTERVAL, 2016);
    }

    #[test]
    fn test_version_info() {
        assert!(!VERSION.is_empty());
        assert!(!NAME.is_empty());
    }
}