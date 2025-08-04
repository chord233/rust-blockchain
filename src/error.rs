//! Error types for the blockchain implementation

use thiserror::Error;

/// Main error type for blockchain operations
#[derive(Error, Debug)]
pub enum BlockchainError {
    #[error("Block validation failed: {0}")]
    BlockValidation(String),

    #[error("Transaction validation failed: {0}")]
    TransactionValidation(String),

    #[error("Insufficient funds: required {required}, available {available}")]
    InsufficientFunds { required: u64, available: u64 },

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid hash: {0}")]
    InvalidHash(String),

    #[error("Block not found: {0}")]
    BlockNotFound(String),

    #[error("Transaction not found: {0}")]
    TransactionNotFound(String),

    #[error("Wallet not found: {0}")]
    WalletNotFound(String),

    #[error("UTXO not found: {0}")]
    UTXONotFound(String),

    #[error("Mining error: {0}")]
    Mining(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Consensus error: {0}")]
    Consensus(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Bincode error: {0}")]
    Bincode(#[from] bincode::Error),

    #[error("Database error: {0}")]
    Database(#[from] sled::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Timeout error: {0}")]
    Timeout(String),

    #[error("Generic error: {0}")]
    Generic(String),
}

/// Result type alias for blockchain operations
pub type Result<T> = std::result::Result<T, BlockchainError>;

// Conversion implementations for common error types
impl From<hex::FromHexError> for BlockchainError {
    fn from(err: hex::FromHexError) -> Self {
        BlockchainError::Parse(format!("Hex decode error: {}", err))
    }
}

impl From<bs58::decode::Error> for BlockchainError {
    fn from(err: bs58::decode::Error) -> Self {
        BlockchainError::Parse(format!("Base58 decode error: {}", err))
    }
}

impl From<secp256k1::Error> for BlockchainError {
    fn from(err: secp256k1::Error) -> Self {
        BlockchainError::Crypto(format!("Secp256k1 error: {}", err))
    }
}

impl From<ring::error::Unspecified> for BlockchainError {
    fn from(_: ring::error::Unspecified) -> Self {
        BlockchainError::Crypto("Ring cryptography error".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = BlockchainError::InsufficientFunds {
            required: 100,
            available: 50,
        };
        assert_eq!(
            err.to_string(),
            "Insufficient funds: required 100, available 50"
        );
    }

    #[test]
    fn test_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let blockchain_err: BlockchainError = io_err.into();
        assert!(matches!(blockchain_err, BlockchainError::Io(_)));
    }

    #[test]
    fn test_result_type() {
        let success: Result<u32> = Ok(42);
        let failure: Result<u32> = Err(BlockchainError::Generic("test error".to_string()));
        
        assert!(success.is_ok());
        assert!(failure.is_err());
    }
}