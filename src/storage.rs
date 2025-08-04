//! Storage implementation for blockchain data persistence

use crate::block::Block;
use crate::crypto::Hash;
use crate::error::{BlockchainError, Result};
use crate::utils::{serialize, deserialize};
use sled::{Db, Tree};
use std::path::Path;
use tracing::{info, warn, error};

/// Storage keys
const BLOCKS_TREE: &str = "blocks";
const BLOCK_HASHES_TREE: &str = "block_hashes";
const METADATA_TREE: &str = "metadata";
const LATEST_HEIGHT_KEY: &str = "latest_height";
const GENESIS_HASH_KEY: &str = "genesis_hash";

/// Storage backend for blockchain data
#[derive(Debug, Clone)]
pub struct Storage {
    /// Main database instance
    db: Db,
    /// Tree for storing blocks by height
    blocks: Tree,
    /// Tree for storing block height by hash
    block_hashes: Tree,
    /// Tree for metadata
    metadata: Tree,
}

impl Storage {
    /// Create a new storage instance
    pub fn new(path: &str) -> Result<Self> {
        info!("Initializing storage at: {}", path);
        
        // Create directory if it doesn't exist
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| BlockchainError::StorageError(
                    format!("Failed to create storage directory: {}", e)
                ))?;
        }
        
        // Open database
        let db = sled::open(path)
            .map_err(|e| BlockchainError::StorageError(
                format!("Failed to open database: {}", e)
            ))?;
        
        // Open trees
        let blocks = db.open_tree(BLOCKS_TREE)
            .map_err(|e| BlockchainError::StorageError(
                format!("Failed to open blocks tree: {}", e)
            ))?;
        
        let block_hashes = db.open_tree(BLOCK_HASHES_TREE)
            .map_err(|e| BlockchainError::StorageError(
                format!("Failed to open block_hashes tree: {}", e)
            ))?;
        
        let metadata = db.open_tree(METADATA_TREE)
            .map_err(|e| BlockchainError::StorageError(
                format!("Failed to open metadata tree: {}", e)
            ))?;
        
        info!("Storage initialized successfully");
        
        Ok(Self {
            db,
            blocks,
            block_hashes,
            metadata,
        })
    }

    /// Store a block
    pub fn store_block(&self, block: &Block) -> Result<()> {
        let height = block.header.height;
        let block_hash = block.hash()?;
        
        info!("Storing block #{} with hash: {}", height, block_hash.to_hex());
        
        // Serialize block
        let block_data = serialize(block)?;
        
        // Store block by height
        let height_key = height.to_be_bytes();
        self.blocks.insert(&height_key, block_data)
            .map_err(|e| BlockchainError::StorageError(
                format!("Failed to store block: {}", e)
            ))?;
        
        // Store height by hash
        let hash_key = block_hash.as_bytes();
        self.block_hashes.insert(hash_key, &height_key)
            .map_err(|e| BlockchainError::StorageError(
                format!("Failed to store block hash mapping: {}", e)
            ))?;
        
        // Store genesis hash if this is the first block
        if height == 0 {
            self.metadata.insert(GENESIS_HASH_KEY, hash_key)
                .map_err(|e| BlockchainError::StorageError(
                    format!("Failed to store genesis hash: {}", e)
                ))?;
        }
        
        // Flush to ensure data is written
        self.db.flush()
            .map_err(|e| BlockchainError::StorageError(
                format!("Failed to flush database: {}", e)
            ))?;
        
        info!("Block #{} stored successfully", height);
        Ok(())
    }

    /// Get a block by height
    pub fn get_block_by_height(&self, height: u64) -> Result<Option<Block>> {
        let height_key = height.to_be_bytes();
        
        match self.blocks.get(&height_key) {
            Ok(Some(data)) => {
                let block: Block = deserialize(&data)?;
                Ok(Some(block))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(BlockchainError::StorageError(
                format!("Failed to get block by height {}: {}", height, e)
            )),
        }
    }

    /// Get a block by hash
    pub fn get_block_by_hash(&self, hash: &Hash) -> Result<Option<Block>> {
        let hash_key = hash.as_bytes();
        
        match self.block_hashes.get(hash_key) {
            Ok(Some(height_data)) => {
                // Convert height bytes back to u64
                if height_data.len() != 8 {
                    return Err(BlockchainError::StorageError(
                        "Invalid height data in block hash mapping".to_string()
                    ));
                }
                
                let mut height_bytes = [0u8; 8];
                height_bytes.copy_from_slice(&height_data);
                let height = u64::from_be_bytes(height_bytes);
                
                self.get_block_by_height(height)
            }
            Ok(None) => Ok(None),
            Err(e) => Err(BlockchainError::StorageError(
                format!("Failed to get block by hash {}: {}", hash.to_hex(), e)
            )),
        }
    }

    /// Get the latest block height
    pub fn get_latest_height(&self) -> Result<u64> {
        match self.metadata.get(LATEST_HEIGHT_KEY) {
            Ok(Some(data)) => {
                if data.len() != 8 {
                    return Err(BlockchainError::StorageError(
                        "Invalid latest height data".to_string()
                    ));
                }
                
                let mut height_bytes = [0u8; 8];
                height_bytes.copy_from_slice(&data);
                Ok(u64::from_be_bytes(height_bytes))
            }
            Ok(None) => Err(BlockchainError::StorageError(
                "Latest height not found".to_string()
            )),
            Err(e) => Err(BlockchainError::StorageError(
                format!("Failed to get latest height: {}", e)
            )),
        }
    }

    /// Set the latest block height
    pub fn set_latest_height(&self, height: u64) -> Result<()> {
        let height_bytes = height.to_be_bytes();
        
        self.metadata.insert(LATEST_HEIGHT_KEY, &height_bytes)
            .map_err(|e| BlockchainError::StorageError(
                format!("Failed to set latest height: {}", e)
            ))?;
        
        self.db.flush()
            .map_err(|e| BlockchainError::StorageError(
                format!("Failed to flush database: {}", e)
            ))?;
        
        Ok(())
    }

    /// Get the genesis block hash
    pub fn get_genesis_hash(&self) -> Result<Option<Hash>> {
        match self.metadata.get(GENESIS_HASH_KEY) {
            Ok(Some(data)) => {
                if data.len() != 32 {
                    return Err(BlockchainError::StorageError(
                        "Invalid genesis hash data".to_string()
                    ));
                }
                
                let mut hash_bytes = [0u8; 32];
                hash_bytes.copy_from_slice(&data);
                Ok(Some(Hash::from_bytes(hash_bytes)))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(BlockchainError::StorageError(
                format!("Failed to get genesis hash: {}", e)
            )),
        }
    }

    /// Check if the storage is empty (no blocks)
    pub fn is_empty(&self) -> Result<bool> {
        match self.blocks.is_empty() {
            true => Ok(true),
            false => Ok(false),
        }
    }

    /// Get storage statistics
    pub fn get_stats(&self) -> Result<StorageStats> {
        let block_count = self.blocks.len();
        let total_size = self.db.size_on_disk()
            .map_err(|e| BlockchainError::StorageError(
                format!("Failed to get database size: {}", e)
            ))?;
        
        let latest_height = match self.get_latest_height() {
            Ok(height) => Some(height),
            Err(_) => None,
        };
        
        let genesis_hash = self.get_genesis_hash()?;
        
        Ok(StorageStats {
            block_count,
            total_size,
            latest_height,
            genesis_hash,
        })
    }

    /// Iterate over all blocks in order
    pub fn iter_blocks(&self) -> Result<Vec<Block>> {
        let mut blocks = Vec::new();
        
        for result in self.blocks.iter() {
            let (key, value) = result
                .map_err(|e| BlockchainError::StorageError(
                    format!("Failed to iterate blocks: {}", e)
                ))?;
            
            // Parse height from key
            if key.len() != 8 {
                warn!("Invalid block key length: {}", key.len());
                continue;
            }
            
            let block: Block = deserialize(&value)?;
            blocks.push(block);
        }
        
        // Sort by height to ensure correct order
        blocks.sort_by_key(|block| block.header.height);
        
        Ok(blocks)
    }

    /// Get blocks in a height range
    pub fn get_blocks_range(&self, start_height: u64, end_height: u64) -> Result<Vec<Block>> {
        let mut blocks = Vec::new();
        
        for height in start_height..=end_height {
            if let Some(block) = self.get_block_by_height(height)? {
                blocks.push(block);
            }
        }
        
        Ok(blocks)
    }

    /// Delete a block by height (dangerous operation)
    pub fn delete_block(&self, height: u64) -> Result<()> {
        warn!("Deleting block at height: {}", height);
        
        // Get block first to get its hash
        if let Some(block) = self.get_block_by_height(height)? {
            let block_hash = block.hash()?;
            
            // Remove from blocks tree
            let height_key = height.to_be_bytes();
            self.blocks.remove(&height_key)
                .map_err(|e| BlockchainError::StorageError(
                    format!("Failed to delete block: {}", e)
                ))?;
            
            // Remove from block hashes tree
            let hash_key = block_hash.as_bytes();
            self.block_hashes.remove(hash_key)
                .map_err(|e| BlockchainError::StorageError(
                    format!("Failed to delete block hash mapping: {}", e)
                ))?;
            
            self.db.flush()
                .map_err(|e| BlockchainError::StorageError(
                    format!("Failed to flush database: {}", e)
                ))?;
            
            info!("Block #{} deleted successfully", height);
        }
        
        Ok(())
    }

    /// Compact the database
    pub fn compact(&self) -> Result<()> {
        info!("Compacting database...");
        
        // Sled doesn't have explicit compaction, but we can flush
        self.db.flush()
            .map_err(|e| BlockchainError::StorageError(
                format!("Failed to compact database: {}", e)
            ))?;
        
        info!("Database compaction completed");
        Ok(())
    }

    /// Close the storage (flush and cleanup)
    pub fn close(&self) -> Result<()> {
        info!("Closing storage...");
        
        self.db.flush()
            .map_err(|e| BlockchainError::StorageError(
                format!("Failed to flush database on close: {}", e)
            ))?;
        
        info!("Storage closed successfully");
        Ok(())
    }
}

/// Storage statistics
#[derive(Debug, Clone)]
pub struct StorageStats {
    /// Number of blocks stored
    pub block_count: usize,
    /// Total size on disk in bytes
    pub total_size: u64,
    /// Latest block height
    pub latest_height: Option<u64>,
    /// Genesis block hash
    pub genesis_hash: Option<Hash>,
}

impl StorageStats {
    /// Format stats as a human-readable string
    pub fn format(&self) -> String {
        format!(
            "Storage Statistics:\n\
            Blocks: {}\n\
            Size: {} bytes ({:.2} MB)\n\
            Latest Height: {}\n\
            Genesis Hash: {}",
            self.block_count,
            self.total_size,
            self.total_size as f64 / 1_048_576.0, // Convert to MB
            self.latest_height.map(|h| h.to_string()).unwrap_or_else(|| "None".to_string()),
            self.genesis_hash.as_ref().map(|h| h.to_hex()).unwrap_or_else(|| "None".to_string())
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::Block;
    use tempfile::TempDir;

    fn create_test_storage() -> (Storage, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let storage = Storage::new(temp_dir.path().to_str().unwrap()).unwrap();
        (storage, temp_dir)
    }

    #[test]
    fn test_storage_creation() {
        let (_storage, _temp_dir) = create_test_storage();
        // Test passes if no panic occurs
    }

    #[test]
    fn test_storage_empty() {
        let (storage, _temp_dir) = create_test_storage();
        assert!(storage.is_empty().unwrap());
    }

    #[test]
    fn test_store_and_retrieve_block() {
        let (storage, _temp_dir) = create_test_storage();
        
        // Create a test block
        let block = Block::genesis("test_address").unwrap();
        let block_hash = block.hash().unwrap();
        
        // Store block
        storage.store_block(&block).unwrap();
        storage.set_latest_height(0).unwrap();
        
        // Retrieve by height
        let retrieved_block = storage.get_block_by_height(0).unwrap().unwrap();
        assert_eq!(retrieved_block.header.height, 0);
        
        // Retrieve by hash
        let retrieved_block = storage.get_block_by_hash(&block_hash).unwrap().unwrap();
        assert_eq!(retrieved_block.header.height, 0);
        
        // Check latest height
        let latest_height = storage.get_latest_height().unwrap();
        assert_eq!(latest_height, 0);
    }

    #[test]
    fn test_genesis_hash() {
        let (storage, _temp_dir) = create_test_storage();
        
        let block = Block::genesis("test_address").unwrap();
        let block_hash = block.hash().unwrap();
        
        storage.store_block(&block).unwrap();
        
        let genesis_hash = storage.get_genesis_hash().unwrap().unwrap();
        assert_eq!(genesis_hash, block_hash);
    }

    #[test]
    fn test_storage_stats() {
        let (storage, _temp_dir) = create_test_storage();
        
        let block = Block::genesis("test_address").unwrap();
        storage.store_block(&block).unwrap();
        storage.set_latest_height(0).unwrap();
        
        let stats = storage.get_stats().unwrap();
        assert_eq!(stats.block_count, 1);
        assert_eq!(stats.latest_height, Some(0));
        assert!(stats.genesis_hash.is_some());
    }

    #[test]
    fn test_iter_blocks() {
        let (storage, _temp_dir) = create_test_storage();
        
        let block = Block::genesis("test_address").unwrap();
        storage.store_block(&block).unwrap();
        
        let blocks = storage.iter_blocks().unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].header.height, 0);
    }

    #[test]
    fn test_get_blocks_range() {
        let (storage, _temp_dir) = create_test_storage();
        
        let block = Block::genesis("test_address").unwrap();
        storage.store_block(&block).unwrap();
        
        let blocks = storage.get_blocks_range(0, 0).unwrap();
        assert_eq!(blocks.len(), 1);
        
        let blocks = storage.get_blocks_range(0, 10).unwrap();
        assert_eq!(blocks.len(), 1); // Only one block exists
    }

    #[test]
    fn test_nonexistent_block() {
        let (storage, _temp_dir) = create_test_storage();
        
        let result = storage.get_block_by_height(999).unwrap();
        assert!(result.is_none());
        
        let hash = Hash::hash(b"nonexistent");
        let result = storage.get_block_by_hash(&hash).unwrap();
        assert!(result.is_none());
    }
}