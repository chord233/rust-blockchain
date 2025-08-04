//! Utility functions for the blockchain implementation

use crate::error::{BlockchainError, Result};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Calculate SHA-256 hash of the input data
pub fn hash_data(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Calculate double SHA-256 hash (Bitcoin-style)
pub fn double_hash(data: &[u8]) -> Vec<u8> {
    let first_hash = hash_data(data);
    hash_data(&first_hash)
}

/// Convert hash bytes to hex string
pub fn hash_to_hex(hash: &[u8]) -> String {
    hex::encode(hash)
}

/// Convert hex string to hash bytes
pub fn hex_to_hash(hex_str: &str) -> Result<Vec<u8>> {
    hex::decode(hex_str).map_err(|e| BlockchainError::Parse(format!("Invalid hex: {}", e)))
}

/// Serialize data using bincode
pub fn serialize<T: serde::Serialize>(data: &T) -> Result<Vec<u8>> {
    bincode::serialize(data).map_err(BlockchainError::from)
}

/// Deserialize data using bincode
pub fn deserialize<T: serde::de::DeserializeOwned>(data: &[u8]) -> Result<T> {
    bincode::deserialize(data).map_err(BlockchainError::from)
}

/// Get current timestamp in seconds since Unix epoch
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

/// Get current timestamp in milliseconds since Unix epoch
pub fn current_timestamp_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis()
}

/// Validate if a string is a valid hex hash
pub fn is_valid_hex_hash(hash: &str, expected_length: usize) -> bool {
    if hash.len() != expected_length * 2 {
        return false;
    }
    hash.chars().all(|c| c.is_ascii_hexdigit())
}

/// Generate a random nonce for mining
pub fn generate_nonce() -> u64 {
    rand::random()
}

/// Check if a hash meets the difficulty target
pub fn meets_difficulty(hash: &[u8], difficulty: usize) -> bool {
    if difficulty == 0 {
        return true;
    }
    
    let hex_hash = hash_to_hex(hash);
    let target = "0".repeat(difficulty);
    hex_hash.starts_with(&target)
}

/// Calculate the difficulty target as a big integer
pub fn calculate_difficulty_target(difficulty: usize) -> num_bigint::BigUint {
    use num_bigint::BigUint;
    use num_traits::{Zero, One};
    
    if difficulty == 0 {
        return BigUint::zero();
    }
    
    // Maximum target (difficulty 1)
    let max_target = BigUint::from(2u32).pow(256) - BigUint::one();
    
    // Calculate target = max_target / (2^difficulty)
    max_target >> difficulty
}

/// Format bytes as human-readable size
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;
    
    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }
    
    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.2} {}", size, UNITS[unit_index])
    }
}

/// Validate Bitcoin-style address format
pub fn is_valid_address(address: &str) -> bool {
    // Basic validation: should be base58 encoded and reasonable length
    if address.len() < 26 || address.len() > 35 {
        return false;
    }
    
    // Try to decode as base58
    bs58::decode(address).into_vec().is_ok()
}

/// Generate a merkle root from a list of transaction hashes
pub fn calculate_merkle_root(tx_hashes: &[Vec<u8>]) -> Vec<u8> {
    if tx_hashes.is_empty() {
        return vec![0; 32]; // Empty merkle root
    }
    
    if tx_hashes.len() == 1 {
        return tx_hashes[0].clone();
    }
    
    let mut current_level = tx_hashes.to_vec();
    
    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        
        for chunk in current_level.chunks(2) {
            let combined = if chunk.len() == 2 {
                [chunk[0].clone(), chunk[1].clone()].concat()
            } else {
                // If odd number, duplicate the last hash
                [chunk[0].clone(), chunk[0].clone()].concat()
            };
            next_level.push(double_hash(&combined));
        }
        
        current_level = next_level;
    }
    
    current_level.into_iter().next().unwrap_or_default()
}

/// Convert satoshis to BTC
pub fn satoshis_to_btc(satoshis: u64) -> f64 {
    satoshis as f64 / 100_000_000.0
}

/// Convert BTC to satoshis
pub fn btc_to_satoshis(btc: f64) -> u64 {
    (btc * 100_000_000.0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_data() {
        let data = b"hello world";
        let hash = hash_data(data);
        assert_eq!(hash.len(), 32); // SHA-256 produces 32-byte hash
    }

    #[test]
    fn test_double_hash() {
        let data = b"test";
        let single_hash = hash_data(data);
        let double_hash_result = double_hash(data);
        let expected = hash_data(&single_hash);
        assert_eq!(double_hash_result, expected);
    }

    #[test]
    fn test_hash_hex_conversion() {
        let data = b"test";
        let hash = hash_data(data);
        let hex = hash_to_hex(&hash);
        let back_to_hash = hex_to_hash(&hex).unwrap();
        assert_eq!(hash, back_to_hash);
    }

    #[test]
    fn test_meets_difficulty() {
        // Create a hash that starts with zeros
        let hash_with_zeros = hex::decode("0000abcd").unwrap();
        assert!(meets_difficulty(&hash_with_zeros, 2));
        assert!(!meets_difficulty(&hash_with_zeros, 5));
    }

    #[test]
    fn test_is_valid_hex_hash() {
        assert!(is_valid_hex_hash("abcd1234", 4));
        assert!(!is_valid_hex_hash("xyz123", 3));
        assert!(!is_valid_hex_hash("ab", 4));
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1048576), "1.00 MB");
        assert_eq!(format_bytes(500), "500 B");
    }

    #[test]
    fn test_merkle_root() {
        let hashes = vec![
            vec![1, 2, 3, 4],
            vec![5, 6, 7, 8],
        ];
        let root = calculate_merkle_root(&hashes);
        assert_eq!(root.len(), 32);
        
        // Empty case
        let empty_root = calculate_merkle_root(&[]);
        assert_eq!(empty_root, vec![0; 32]);
    }

    #[test]
    fn test_btc_conversion() {
        assert_eq!(satoshis_to_btc(100_000_000), 1.0);
        assert_eq!(btc_to_satoshis(1.0), 100_000_000);
        assert_eq!(satoshis_to_btc(50_000_000), 0.5);
    }

    #[test]
    fn test_serialize_deserialize() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct TestData {
            value: u32,
            text: String,
        }
        
        let original = TestData {
            value: 42,
            text: "hello".to_string(),
        };
        
        let serialized = serialize(&original).unwrap();
        let deserialized: TestData = deserialize(&serialized).unwrap();
        
        assert_eq!(original, deserialized);
    }
}