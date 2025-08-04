//! Cryptographic primitives for the blockchain

use crate::error::{BlockchainError, Result};
use crate::utils::{hash_data, double_hash};
use secp256k1::{ecdsa::Signature as Secp256k1Signature, Message, PublicKey, SecretKey, Secp256k1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// A cryptographic hash (32 bytes)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    /// Create a new hash from bytes
    pub fn new(data: [u8; 32]) -> Self {
        Hash(data)
    }

    /// Create hash from slice
    pub fn from_slice(data: &[u8]) -> Result<Self> {
        if data.len() != 32 {
            return Err(BlockchainError::InvalidHash(
                "Hash must be exactly 32 bytes".to_string(),
            ));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(data);
        Ok(Hash(hash))
    }

    /// Get hash as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Create hash from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| BlockchainError::InvalidHash(format!("Invalid hex: {}", e)))?;
        Self::from_slice(&bytes)
    }

    /// Calculate hash of data
    pub fn hash(data: &[u8]) -> Self {
        let hash_bytes = hash_data(data);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_bytes);
        Hash(hash)
    }

    /// Calculate double hash of data (Bitcoin-style)
    pub fn double_hash(data: &[u8]) -> Self {
        let hash_bytes = double_hash(data);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_bytes);
        Hash(hash)
    }

    /// Zero hash
    pub fn zero() -> Self {
        Hash([0u8; 32])
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Default for Hash {
    fn default() -> Self {
        Self::zero()
    }
}

/// Digital signature
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub recovery_id: u8,
}

impl Signature {
    /// Create signature from DER bytes
    pub fn from_der(der_bytes: &[u8]) -> Result<Self> {
        let sig = Secp256k1Signature::from_der(der_bytes)
            .map_err(|e| BlockchainError::InvalidSignature)?;
        
        let (r, s) = sig.as_ref().split_at(32);
        let mut r_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];
        r_bytes.copy_from_slice(r);
        s_bytes.copy_from_slice(s);
        
        Ok(Signature {
            r: r_bytes,
            s: s_bytes,
            recovery_id: 0, // Default recovery ID
        })
    }

    /// Convert to DER bytes
    pub fn to_der(&self) -> Result<Vec<u8>> {
        let combined = [self.r.as_slice(), self.s.as_slice()].concat();
        let sig = Secp256k1Signature::from_compact(&combined)
            .map_err(|_| BlockchainError::InvalidSignature)?;
        Ok(sig.serialize_der().to_vec())
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode([self.r.as_slice(), self.s.as_slice()].concat())
    }

    /// Create from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| BlockchainError::Parse(format!("Invalid hex: {}", e)))?;
        
        if bytes.len() != 64 {
            return Err(BlockchainError::InvalidSignature);
        }
        
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[0..32]);
        s.copy_from_slice(&bytes[32..64]);
        
        Ok(Signature {
            r,
            s,
            recovery_id: 0,
        })
    }
}

/// Cryptographic key pair for signing and verification
#[derive(Debug, Clone)]
pub struct KeyPair {
    secret_key: SecretKey,
    public_key: PublicKey,
    secp: Secp256k1<secp256k1::All>,
}

impl KeyPair {
    /// Generate a new random key pair
    pub fn generate() -> Result<Self> {
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());
        
        Ok(KeyPair {
            secret_key,
            public_key,
            secp,
        })
    }

    /// Create key pair from secret key bytes
    pub fn from_secret_key(secret_bytes: &[u8]) -> Result<Self> {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(secret_bytes)
            .map_err(|e| BlockchainError::Crypto(format!("Invalid secret key: {}", e)))?;
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        
        Ok(KeyPair {
            secret_key,
            public_key,
            secp,
        })
    }

    /// Get public key bytes (compressed)
    pub fn public_key_bytes(&self) -> [u8; 33] {
        self.public_key.serialize()
    }

    /// Get secret key bytes
    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.secret_key.secret_bytes()
    }

    /// Get public key as hex string
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key_bytes())
    }

    /// Get secret key as hex string (be careful with this!)
    pub fn secret_key_hex(&self) -> String {
        hex::encode(self.secret_key_bytes())
    }

    /// Sign a message hash
    pub fn sign(&self, message_hash: &Hash) -> Result<Signature> {
        let message = Message::from_slice(message_hash.as_bytes())
            .map_err(|e| BlockchainError::Crypto(format!("Invalid message: {}", e)))?;
        
        let signature = self.secp.sign_ecdsa(&message, &self.secret_key);
        let (r, s) = signature.as_ref().split_at(32);
        
        let mut r_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];
        r_bytes.copy_from_slice(r);
        s_bytes.copy_from_slice(s);
        
        Ok(Signature {
            r: r_bytes,
            s: s_bytes,
            recovery_id: 0,
        })
    }

    /// Verify a signature
    pub fn verify(&self, message_hash: &Hash, signature: &Signature) -> bool {
        self.verify_with_public_key(&self.public_key, message_hash, signature)
    }

    /// Verify signature with a specific public key
    pub fn verify_with_public_key(
        &self,
        public_key: &PublicKey,
        message_hash: &Hash,
        signature: &Signature,
    ) -> bool {
        let message = match Message::from_slice(message_hash.as_bytes()) {
            Ok(msg) => msg,
            Err(_) => return false,
        };
        
        let combined = [signature.r.as_slice(), signature.s.as_slice()].concat();
        let sig = match Secp256k1Signature::from_compact(&combined) {
            Ok(sig) => sig,
            Err(_) => return false,
        };
        
        self.secp.verify_ecdsa(&message, &sig, public_key).is_ok()
    }

    /// Generate Bitcoin-style address from public key
    pub fn generate_address(&self) -> String {
        let public_key_bytes = self.public_key_bytes();
        
        // Hash the public key with SHA-256
        let sha256_hash = hash_data(&public_key_bytes);
        
        // Hash again with RIPEMD-160 (we'll use SHA-256 for simplicity)
        let ripemd_hash = hash_data(&sha256_hash);
        
        // Take first 20 bytes
        let mut address_bytes = vec![0x00]; // Version byte for mainnet
        address_bytes.extend_from_slice(&ripemd_hash[..20]);
        
        // Calculate checksum (double SHA-256 of version + hash)
        let checksum_hash = double_hash(&address_bytes);
        address_bytes.extend_from_slice(&checksum_hash[..4]);
        
        // Encode with Base58
        bs58::encode(address_bytes).into_string()
    }
}

/// Verify an address is valid
pub fn verify_address(address: &str) -> bool {
    // Decode Base58
    let decoded = match bs58::decode(address).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    
    // Check length (1 version + 20 hash + 4 checksum = 25 bytes)
    if decoded.len() != 25 {
        return false;
    }
    
    // Verify checksum
    let (payload, checksum) = decoded.split_at(21);
    let calculated_checksum = double_hash(payload);
    
    checksum == &calculated_checksum[..4]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_creation() {
        let data = b"hello world";
        let hash = Hash::hash(data);
        assert_eq!(hash.as_bytes().len(), 32);
        
        let hex = hash.to_hex();
        let hash_from_hex = Hash::from_hex(&hex).unwrap();
        assert_eq!(hash, hash_from_hex);
    }

    #[test]
    fn test_keypair_generation() {
        let keypair = KeyPair::generate().unwrap();
        assert_eq!(keypair.public_key_bytes().len(), 33);
        assert_eq!(keypair.secret_key_bytes().len(), 32);
    }

    #[test]
    fn test_signing_and_verification() {
        let keypair = KeyPair::generate().unwrap();
        let message = Hash::hash(b"test message");
        
        let signature = keypair.sign(&message).unwrap();
        assert!(keypair.verify(&message, &signature));
        
        // Test with different message
        let different_message = Hash::hash(b"different message");
        assert!(!keypair.verify(&different_message, &signature));
    }

    #[test]
    fn test_address_generation() {
        let keypair = KeyPair::generate().unwrap();
        let address = keypair.generate_address();
        
        assert!(!address.is_empty());
        assert!(verify_address(&address));
    }

    #[test]
    fn test_signature_serialization() {
        let keypair = KeyPair::generate().unwrap();
        let message = Hash::hash(b"test");
        let signature = keypair.sign(&message).unwrap();
        
        let hex = signature.to_hex();
        let signature_from_hex = Signature::from_hex(&hex).unwrap();
        
        assert_eq!(signature.r, signature_from_hex.r);
        assert_eq!(signature.s, signature_from_hex.s);
    }

    #[test]
    fn test_double_hash() {
        let data = b"test";
        let single = Hash::hash(data);
        let double = Hash::double_hash(data);
        
        assert_ne!(single, double);
        assert_eq!(double, Hash::hash(single.as_bytes()));
    }
}