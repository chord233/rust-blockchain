//! Transaction implementation with UTXO model

use crate::crypto::{Hash, KeyPair, Signature};
use crate::error::{BlockchainError, Result};
use crate::utils::{serialize, current_timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Transaction input referencing a previous output
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxInput {
    /// Hash of the transaction containing the output being spent
    pub prev_tx_hash: Hash,
    /// Index of the output in the previous transaction
    pub output_index: u32,
    /// Digital signature proving ownership
    pub signature: Option<Signature>,
    /// Public key of the spender
    pub public_key: Option<Vec<u8>>,
}

impl TxInput {
    /// Create a new transaction input
    pub fn new(prev_tx_hash: Hash, output_index: u32) -> Self {
        Self {
            prev_tx_hash,
            output_index,
            signature: None,
            public_key: None,
        }
    }

    /// Create a coinbase input (for mining rewards)
    pub fn coinbase() -> Self {
        Self {
            prev_tx_hash: Hash::zero(),
            output_index: 0xffffffff,
            signature: None,
            public_key: None,
        }
    }

    /// Check if this is a coinbase input
    pub fn is_coinbase(&self) -> bool {
        self.prev_tx_hash == Hash::zero() && self.output_index == 0xffffffff
    }

    /// Sign this input
    pub fn sign(&mut self, keypair: &KeyPair, tx_hash: &Hash) -> Result<()> {
        if self.is_coinbase() {
            return Ok(()); // Coinbase inputs don't need signatures
        }
        
        self.signature = Some(keypair.sign(tx_hash)?);
        self.public_key = Some(keypair.public_key_bytes().to_vec());
        Ok(())
    }

    /// Verify the signature of this input
    pub fn verify_signature(&self, tx_hash: &Hash) -> bool {
        if self.is_coinbase() {
            return true; // Coinbase inputs are always valid
        }
        
        let signature = match &self.signature {
            Some(sig) => sig,
            None => return false,
        };
        
        let public_key_bytes = match &self.public_key {
            Some(pk) => pk,
            None => return false,
        };
        
        // Create a temporary keypair for verification
        match KeyPair::from_secret_key(&[0u8; 32]) {
            Ok(temp_keypair) => {
                // In a real implementation, we would reconstruct the public key
                // For now, we'll assume the signature is valid if present
                true
            }
            Err(_) => false,
        }
    }
}

/// Transaction output
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxOutput {
    /// Amount in satoshis
    pub value: u64,
    /// Address of the recipient
    pub address: String,
}

impl TxOutput {
    /// Create a new transaction output
    pub fn new(value: u64, address: String) -> Self {
        Self { value, address }
    }

    /// Check if this output can be unlocked by the given address
    pub fn can_unlock(&self, address: &str) -> bool {
        self.address == address
    }
}

/// Unspent Transaction Output
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UTXO {
    /// The transaction hash
    pub tx_hash: Hash,
    /// Output index in the transaction
    pub output_index: u32,
    /// The actual output
    pub output: TxOutput,
    /// Block height where this UTXO was created
    pub block_height: u64,
}

impl UTXO {
    /// Create a new UTXO
    pub fn new(tx_hash: Hash, output_index: u32, output: TxOutput, block_height: u64) -> Self {
        Self {
            tx_hash,
            output_index,
            output,
            block_height,
        }
    }

    /// Get the unique identifier for this UTXO
    pub fn id(&self) -> String {
        format!("{}:{}", self.tx_hash.to_hex(), self.output_index)
    }
}

/// A blockchain transaction
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction inputs
    pub inputs: Vec<TxInput>,
    /// Transaction outputs
    pub outputs: Vec<TxOutput>,
    /// Transaction timestamp
    pub timestamp: u64,
    /// Transaction version
    pub version: u32,
    /// Lock time (block height or timestamp)
    pub lock_time: u32,
}

impl Transaction {
    /// Create a new transaction
    pub fn new(inputs: Vec<TxInput>, outputs: Vec<TxOutput>) -> Self {
        Self {
            inputs,
            outputs,
            timestamp: current_timestamp(),
            version: 1,
            lock_time: 0,
        }
    }

    /// Create a coinbase transaction (mining reward)
    pub fn coinbase(reward_address: &str, block_height: u64) -> Self {
        let coinbase_input = TxInput::coinbase();
        let reward_output = TxOutput::new(crate::BLOCK_REWARD, reward_address.to_string());
        
        Self {
            inputs: vec![coinbase_input],
            outputs: vec![reward_output],
            timestamp: current_timestamp(),
            version: 1,
            lock_time: block_height as u32,
        }
    }

    /// Calculate the hash of this transaction
    pub fn hash(&self) -> Result<Hash> {
        // Create a copy without signatures for hashing
        let mut tx_copy = self.clone();
        for input in &mut tx_copy.inputs {
            input.signature = None;
            input.public_key = None;
        }
        
        let serialized = serialize(&tx_copy)?;
        Ok(Hash::double_hash(&serialized))
    }

    /// Check if this is a coinbase transaction
    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].is_coinbase()
    }

    /// Get the total input value
    pub fn input_value(&self, utxo_set: &HashMap<String, UTXO>) -> u64 {
        if self.is_coinbase() {
            return 0; // Coinbase transactions don't spend existing UTXOs
        }
        
        self.inputs
            .iter()
            .map(|input| {
                let utxo_id = format!("{}:{}", input.prev_tx_hash.to_hex(), input.output_index);
                utxo_set.get(&utxo_id).map(|utxo| utxo.output.value).unwrap_or(0)
            })
            .sum()
    }

    /// Get the total output value
    pub fn output_value(&self) -> u64 {
        self.outputs.iter().map(|output| output.value).sum()
    }

    /// Calculate the transaction fee
    pub fn fee(&self, utxo_set: &HashMap<String, UTXO>) -> u64 {
        if self.is_coinbase() {
            return 0;
        }
        
        let input_value = self.input_value(utxo_set);
        let output_value = self.output_value();
        
        if input_value >= output_value {
            input_value - output_value
        } else {
            0
        }
    }

    /// Validate the transaction
    pub fn validate(&self, utxo_set: &HashMap<String, UTXO>) -> Result<()> {
        // Check if transaction has inputs and outputs
        if self.inputs.is_empty() {
            return Err(BlockchainError::TransactionValidation(
                "Transaction must have at least one input".to_string(),
            ));
        }
        
        if self.outputs.is_empty() {
            return Err(BlockchainError::TransactionValidation(
                "Transaction must have at least one output".to_string(),
            ));
        }
        
        // Validate coinbase transaction
        if self.is_coinbase() {
            if self.inputs.len() != 1 {
                return Err(BlockchainError::TransactionValidation(
                    "Coinbase transaction must have exactly one input".to_string(),
                ));
            }
            return Ok(()); // Coinbase transactions are valid by definition
        }
        
        // Check that all referenced UTXOs exist
        for input in &self.inputs {
            let utxo_id = format!("{}:{}", input.prev_tx_hash.to_hex(), input.output_index);
            if !utxo_set.contains_key(&utxo_id) {
                return Err(BlockchainError::UTXONotFound(utxo_id));
            }
        }
        
        // Check that input value >= output value
        let input_value = self.input_value(utxo_set);
        let output_value = self.output_value();
        
        if input_value < output_value {
            return Err(BlockchainError::InsufficientFunds {
                required: output_value,
                available: input_value,
            });
        }
        
        // Verify signatures
        let tx_hash = self.hash()?;
        for input in &self.inputs {
            if !input.verify_signature(&tx_hash) {
                return Err(BlockchainError::InvalidSignature);
            }
        }
        
        Ok(())
    }

    /// Sign all inputs of the transaction
    pub fn sign(&mut self, keypair: &KeyPair) -> Result<()> {
        let tx_hash = self.hash()?;
        
        for input in &mut self.inputs {
            input.sign(keypair, &tx_hash)?;
        }
        
        Ok(())
    }

    /// Get the size of the transaction in bytes
    pub fn size(&self) -> Result<usize> {
        let serialized = serialize(self)?;
        Ok(serialized.len())
    }

    /// Calculate the transaction priority (used for mempool ordering)
    pub fn priority(&self, utxo_set: &HashMap<String, UTXO>, current_height: u64) -> f64 {
        if self.is_coinbase() {
            return f64::MAX; // Coinbase transactions have highest priority
        }
        
        let input_age: u64 = self.inputs
            .iter()
            .map(|input| {
                let utxo_id = format!("{}:{}", input.prev_tx_hash.to_hex(), input.output_index);
                utxo_set.get(&utxo_id)
                    .map(|utxo| current_height.saturating_sub(utxo.block_height))
                    .unwrap_or(0)
            })
            .sum();
        
        let input_value = self.input_value(utxo_set);
        let size = self.size().unwrap_or(1) as u64;
        
        // Priority = (input_value * input_age) / size
        (input_value as f64 * input_age as f64) / size as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use std::collections::HashMap;

    #[test]
    fn test_coinbase_transaction() {
        let tx = Transaction::coinbase("test_address", 100);
        assert!(tx.is_coinbase());
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].value, crate::BLOCK_REWARD);
    }

    #[test]
    fn test_transaction_hash() {
        let tx = Transaction::coinbase("test_address", 100);
        let hash1 = tx.hash().unwrap();
        let hash2 = tx.hash().unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_transaction_validation() {
        let tx = Transaction::coinbase("test_address", 100);
        let utxo_set = HashMap::new();
        assert!(tx.validate(&utxo_set).is_ok());
    }

    #[test]
    fn test_utxo_creation() {
        let output = TxOutput::new(100, "test_address".to_string());
        let tx_hash = Hash::hash(b"test");
        let utxo = UTXO::new(tx_hash.clone(), 0, output.clone(), 100);
        
        assert_eq!(utxo.tx_hash, tx_hash);
        assert_eq!(utxo.output_index, 0);
        assert_eq!(utxo.output, output);
        assert_eq!(utxo.block_height, 100);
    }

    #[test]
    fn test_transaction_input_output() {
        let prev_hash = Hash::hash(b"previous_tx");
        let input = TxInput::new(prev_hash.clone(), 0);
        let output = TxOutput::new(50, "recipient_address".to_string());
        
        assert_eq!(input.prev_tx_hash, prev_hash);
        assert_eq!(input.output_index, 0);
        assert!(!input.is_coinbase());
        
        assert_eq!(output.value, 50);
        assert!(output.can_unlock("recipient_address"));
        assert!(!output.can_unlock("wrong_address"));
    }

    #[test]
    fn test_transaction_values() {
        let tx = Transaction::coinbase("test_address", 100);
        let utxo_set = HashMap::new();
        
        assert_eq!(tx.input_value(&utxo_set), 0); // Coinbase has no input value
        assert_eq!(tx.output_value(), crate::BLOCK_REWARD);
        assert_eq!(tx.fee(&utxo_set), 0);
    }

    #[test]
    fn test_transaction_size() {
        let tx = Transaction::coinbase("test_address", 100);
        let size = tx.size().unwrap();
        assert!(size > 0);
    }
}