//! Wallet implementation for managing keys and creating transactions

use crate::blockchain::Blockchain;
use crate::crypto::{Hash, KeyPair};
use crate::error::{BlockchainError, Result};
use crate::transaction::{Transaction, TxInput, TxOutput};
use crate::utils::{serialize, deserialize};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tracing::{info, warn};

/// Wallet data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletData {
    /// Wallet name/identifier
    pub name: String,
    /// Private key (32 bytes)
    pub private_key: [u8; 32],
    /// Public key bytes
    pub public_key: Vec<u8>,
    /// Bitcoin-style address
    pub address: String,
    /// Creation timestamp
    pub created_at: u64,
}

impl WalletData {
    /// Create a new wallet with random keys
    pub fn new(name: String) -> Result<Self> {
        let keypair = KeyPair::generate()?;
        let address = keypair.address();
        
        Ok(Self {
            name,
            private_key: keypair.private_key_bytes(),
            public_key: keypair.public_key_bytes().to_vec(),
            address,
            created_at: crate::utils::current_timestamp(),
        })
    }

    /// Create wallet from existing private key
    pub fn from_private_key(name: String, private_key: [u8; 32]) -> Result<Self> {
        let keypair = KeyPair::from_secret_key(&private_key)?;
        let address = keypair.address();
        
        Ok(Self {
            name,
            private_key,
            public_key: keypair.public_key_bytes().to_vec(),
            address,
            created_at: crate::utils::current_timestamp(),
        })
    }

    /// Get the keypair for this wallet
    pub fn keypair(&self) -> Result<KeyPair> {
        KeyPair::from_secret_key(&self.private_key)
    }

    /// Get wallet info as formatted string
    pub fn info(&self) -> String {
        format!(
            "Wallet: {}\n\
            Address: {}\n\
            Created: {}\n\
            Private Key: {}\n\
            Public Key: {}",
            self.name,
            self.address,
            chrono::DateTime::from_timestamp(self.created_at as i64, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| "Invalid timestamp".to_string()),
            hex::encode(&self.private_key),
            hex::encode(&self.public_key)
        )
    }
}

/// Wallet manager for handling multiple wallets
#[derive(Debug)]
pub struct WalletManager {
    /// Directory where wallets are stored
    wallet_dir: String,
    /// Loaded wallets
    wallets: HashMap<String, WalletData>,
}

impl WalletManager {
    /// Create a new wallet manager
    pub fn new(wallet_dir: &str) -> Result<Self> {
        // Create wallet directory if it doesn't exist
        fs::create_dir_all(wallet_dir)
            .map_err(|e| BlockchainError::StorageError(format!("Failed to create wallet directory: {}", e)))?;
        
        let mut manager = Self {
            wallet_dir: wallet_dir.to_string(),
            wallets: HashMap::new(),
        };
        
        // Load existing wallets
        manager.load_wallets()?;
        
        Ok(manager)
    }

    /// Load all wallets from disk
    fn load_wallets(&mut self) -> Result<()> {
        let wallet_dir = Path::new(&self.wallet_dir);
        
        if !wallet_dir.exists() {
            return Ok(());
        }
        
        for entry in fs::read_dir(wallet_dir)
            .map_err(|e| BlockchainError::StorageError(format!("Failed to read wallet directory: {}", e)))? {
            let entry = entry
                .map_err(|e| BlockchainError::StorageError(format!("Failed to read directory entry: {}", e)))?;
            
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("wallet") {
                if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                    match self.load_wallet_file(&path) {
                        Ok(wallet) => {
                            self.wallets.insert(name.to_string(), wallet);
                            info!("Loaded wallet: {}", name);
                        }
                        Err(e) => {
                            warn!("Failed to load wallet {}: {}", name, e);
                        }
                    }
                }
            }
        }
        
        info!("Loaded {} wallets", self.wallets.len());
        Ok(())
    }

    /// Load a single wallet file
    fn load_wallet_file(&self, path: &Path) -> Result<WalletData> {
        let data = fs::read(path)
            .map_err(|e| BlockchainError::StorageError(format!("Failed to read wallet file: {}", e)))?;
        
        deserialize(&data)
    }

    /// Save a wallet to disk
    fn save_wallet(&self, wallet: &WalletData) -> Result<()> {
        let wallet_path = Path::new(&self.wallet_dir).join(format!("{}.wallet", wallet.name));
        let data = serialize(wallet)?;
        
        fs::write(&wallet_path, data)
            .map_err(|e| BlockchainError::StorageError(format!("Failed to save wallet: {}", e)))?;
        
        info!("Saved wallet: {} to {:?}", wallet.name, wallet_path);
        Ok(())
    }

    /// Create a new wallet
    pub fn create_wallet(&mut self, name: &str) -> Result<String> {
        if self.wallets.contains_key(name) {
            return Err(BlockchainError::WalletError(
                format!("Wallet '{}' already exists", name)
            ));
        }
        
        let wallet = WalletData::new(name.to_string())?;
        let address = wallet.address.clone();
        
        // Save to disk
        self.save_wallet(&wallet)?;
        
        // Add to memory
        self.wallets.insert(name.to_string(), wallet);
        
        info!("Created new wallet: {} with address: {}", name, address);
        Ok(address)
    }

    /// Import a wallet from private key
    pub fn import_wallet(&mut self, name: &str, private_key_hex: &str) -> Result<String> {
        if self.wallets.contains_key(name) {
            return Err(BlockchainError::WalletError(
                format!("Wallet '{}' already exists", name)
            ));
        }
        
        // Parse private key
        let private_key_bytes = hex::decode(private_key_hex)
            .map_err(|_| BlockchainError::InvalidAddress("Invalid private key format".to_string()))?;
        
        if private_key_bytes.len() != 32 {
            return Err(BlockchainError::InvalidAddress(
                "Private key must be 32 bytes".to_string()
            ));
        }
        
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&private_key_bytes);
        
        let wallet = WalletData::from_private_key(name.to_string(), private_key)?;
        let address = wallet.address.clone();
        
        // Save to disk
        self.save_wallet(&wallet)?;
        
        // Add to memory
        self.wallets.insert(name.to_string(), wallet);
        
        info!("Imported wallet: {} with address: {}", name, address);
        Ok(address)
    }

    /// Get a wallet by name
    pub fn get_wallet(&self, name: &str) -> Option<&WalletData> {
        self.wallets.get(name)
    }

    /// List all wallet names
    pub fn list_wallets(&self) -> Vec<String> {
        self.wallets.keys().cloned().collect()
    }

    /// Get wallet info
    pub fn get_wallet_info(&self, name: &str) -> Result<String> {
        let wallet = self.wallets.get(name)
            .ok_or_else(|| BlockchainError::WalletError(
                format!("Wallet '{}' not found", name)
            ))?;
        
        Ok(wallet.info())
    }

    /// Get wallet balance
    pub fn get_balance(&self, name: &str, blockchain: &Blockchain) -> Result<u64> {
        let wallet = self.wallets.get(name)
            .ok_or_else(|| BlockchainError::WalletError(
                format!("Wallet '{}' not found", name)
            ))?;
        
        Ok(blockchain.get_balance(&wallet.address))
    }

    /// Create a transaction
    pub fn create_transaction(
        &self,
        from_wallet: &str,
        to_address: &str,
        amount: u64,
        blockchain: &Blockchain,
    ) -> Result<Transaction> {
        let wallet = self.wallets.get(from_wallet)
            .ok_or_else(|| BlockchainError::WalletError(
                format!("Wallet '{}' not found", from_wallet)
            ))?;
        
        // Validate recipient address
        if !crate::utils::is_valid_address(to_address) {
            return Err(BlockchainError::InvalidAddress(
                "Invalid recipient address".to_string()
            ));
        }
        
        // Find spendable UTXOs
        let (utxos, total_input) = blockchain.find_spendable_utxos(&wallet.address, amount)?;
        
        // Create transaction inputs
        let mut inputs = Vec::new();
        for utxo in &utxos {
            let input = TxInput::new(utxo.tx_hash.clone(), utxo.output_index);
            inputs.push(input);
        }
        
        // Create transaction outputs
        let mut outputs = Vec::new();
        
        // Output to recipient
        outputs.push(TxOutput::new(amount, to_address.to_string()));
        
        // Change output (if needed)
        if total_input > amount {
            let change = total_input - amount;
            outputs.push(TxOutput::new(change, wallet.address.clone()));
        }
        
        // Create and sign transaction
        let mut transaction = Transaction::new(inputs, outputs);
        let keypair = wallet.keypair()?;
        transaction.sign(&keypair)?;
        
        info!("Created transaction: {} -> {} ({} satoshis)", 
              wallet.address, to_address, amount);
        
        Ok(transaction)
    }

    /// Send a transaction
    pub fn send_transaction(
        &self,
        from_wallet: &str,
        to_address: &str,
        amount: u64,
        blockchain: &mut Blockchain,
    ) -> Result<Hash> {
        // Create transaction
        let transaction = self.create_transaction(from_wallet, to_address, amount, blockchain)?;
        let tx_hash = transaction.hash()?;
        
        // Create a new block with this transaction
        let coinbase_tx = Transaction::coinbase(&self.get_wallet(from_wallet).unwrap().address, blockchain.height() + 1);
        let transactions = vec![coinbase_tx, transaction];
        
        let new_block = crate::block::Block::new(
            blockchain.latest_block_hash().clone(),
            transactions,
            blockchain.difficulty(),
            blockchain.height() + 1,
        )?;
        
        // Add block to blockchain
        blockchain.add_block(new_block)?;
        
        info!("Transaction {} sent successfully", tx_hash.to_hex());
        Ok(tx_hash)
    }

    /// Delete a wallet
    pub fn delete_wallet(&mut self, name: &str) -> Result<()> {
        if !self.wallets.contains_key(name) {
            return Err(BlockchainError::WalletError(
                format!("Wallet '{}' not found", name)
            ));
        }
        
        // Remove from memory
        self.wallets.remove(name);
        
        // Remove from disk
        let wallet_path = Path::new(&self.wallet_dir).join(format!("{}.wallet", name));
        if wallet_path.exists() {
            fs::remove_file(&wallet_path)
                .map_err(|e| BlockchainError::StorageError(format!("Failed to delete wallet file: {}", e)))?;
        }
        
        info!("Deleted wallet: {}", name);
        Ok(())
    }

    /// Export wallet private key
    pub fn export_private_key(&self, name: &str) -> Result<String> {
        let wallet = self.wallets.get(name)
            .ok_or_else(|| BlockchainError::WalletError(
                format!("Wallet '{}' not found", name)
            ))?;
        
        Ok(hex::encode(&wallet.private_key))
    }

    /// Get wallet address
    pub fn get_address(&self, name: &str) -> Result<String> {
        let wallet = self.wallets.get(name)
            .ok_or_else(|| BlockchainError::WalletError(
                format!("Wallet '{}' not found", name)
            ))?;
        
        Ok(wallet.address.clone())
    }

    /// List all wallets with their info
    pub fn list_wallets_detailed(&self, blockchain: &Blockchain) -> Vec<(String, String, u64)> {
        self.wallets
            .iter()
            .map(|(name, wallet)| {
                let balance = blockchain.get_balance(&wallet.address);
                (name.clone(), wallet.address.clone(), balance)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_wallet_manager() -> (WalletManager, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let manager = WalletManager::new(temp_dir.path().to_str().unwrap()).unwrap();
        (manager, temp_dir)
    }

    #[test]
    fn test_wallet_creation() {
        let wallet = WalletData::new("test_wallet".to_string()).unwrap();
        assert_eq!(wallet.name, "test_wallet");
        assert!(!wallet.address.is_empty());
        assert_eq!(wallet.private_key.len(), 32);
    }

    #[test]
    fn test_wallet_from_private_key() {
        let private_key = [1u8; 32];
        let wallet = WalletData::from_private_key("test_wallet".to_string(), private_key).unwrap();
        assert_eq!(wallet.private_key, private_key);
    }

    #[test]
    fn test_wallet_manager_creation() {
        let (_manager, _temp_dir) = create_test_wallet_manager();
        // Test passes if no panic occurs
    }

    #[test]
    fn test_create_wallet() {
        let (mut manager, _temp_dir) = create_test_wallet_manager();
        let address = manager.create_wallet("test_wallet").unwrap();
        assert!(!address.is_empty());
        assert!(manager.get_wallet("test_wallet").is_some());
    }

    #[test]
    fn test_duplicate_wallet_creation() {
        let (mut manager, _temp_dir) = create_test_wallet_manager();
        manager.create_wallet("test_wallet").unwrap();
        let result = manager.create_wallet("test_wallet");
        assert!(result.is_err());
    }

    #[test]
    fn test_import_wallet() {
        let (mut manager, _temp_dir) = create_test_wallet_manager();
        let private_key_hex = hex::encode([1u8; 32]);
        let address = manager.import_wallet("imported_wallet", &private_key_hex).unwrap();
        assert!(!address.is_empty());
        assert!(manager.get_wallet("imported_wallet").is_some());
    }

    #[test]
    fn test_list_wallets() {
        let (mut manager, _temp_dir) = create_test_wallet_manager();
        manager.create_wallet("wallet1").unwrap();
        manager.create_wallet("wallet2").unwrap();
        
        let wallets = manager.list_wallets();
        assert_eq!(wallets.len(), 2);
        assert!(wallets.contains(&"wallet1".to_string()));
        assert!(wallets.contains(&"wallet2".to_string()));
    }

    #[test]
    fn test_export_private_key() {
        let (mut manager, _temp_dir) = create_test_wallet_manager();
        manager.create_wallet("test_wallet").unwrap();
        let private_key = manager.export_private_key("test_wallet").unwrap();
        assert_eq!(private_key.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_get_address() {
        let (mut manager, _temp_dir) = create_test_wallet_manager();
        let created_address = manager.create_wallet("test_wallet").unwrap();
        let retrieved_address = manager.get_address("test_wallet").unwrap();
        assert_eq!(created_address, retrieved_address);
    }

    #[test]
    fn test_wallet_info() {
        let wallet = WalletData::new("test_wallet".to_string()).unwrap();
        let info = wallet.info();
        assert!(info.contains("test_wallet"));
        assert!(info.contains(&wallet.address));
    }
}