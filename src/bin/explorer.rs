//! Blockchain explorer binary
//!
//! A command-line blockchain explorer that provides detailed information
//! about blocks, transactions, addresses, and network statistics.

use anyhow::Result;
use clap::{Arg, Command, SubCommand};
use rust_blockchain::{
    blockchain::Blockchain,
    storage::Storage,
    transaction::Transaction,
    utils,
};
use serde_json;
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{error, info};
use tracing_subscriber;

/// Explorer configuration
#[derive(Debug, Clone)]
struct ExplorerConfig {
    /// Data directory
    data_dir: PathBuf,
    /// Output format (json, table, detailed)
    output_format: String,
    /// Log level
    log_level: String,
}

impl Default for ExplorerConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data"),
            output_format: "table".to_string(),
            log_level: "warn".to_string(),
        }
    }
}

/// Blockchain explorer
struct BlockchainExplorer {
    blockchain: Blockchain,
    config: ExplorerConfig,
}

impl BlockchainExplorer {
    /// Create a new blockchain explorer
    fn new(config: ExplorerConfig) -> Result<Self> {
        let storage_path = config.data_dir.join("blockchain");
        let storage = Storage::new(&storage_path)?;
        
        if storage.is_empty()? {
            return Err(anyhow::anyhow!(
                "No blockchain found in data directory: {:?}",
                config.data_dir
            ));
        }
        
        let blockchain = Blockchain::load(storage)?;
        
        Ok(Self { blockchain, config })
    }
    
    /// Show blockchain overview
    fn show_overview(&self) -> Result<()> {
        let stats = self.blockchain.get_stats();
        let latest_block = self.blockchain.get_latest_block()?;
        
        match self.config.output_format.as_str() {
            "json" => {
                let overview = serde_json::json!({
                    "height": stats.height,
                    "total_blocks": stats.total_blocks,
                    "total_transactions": stats.total_transactions,
                    "total_utxos": stats.total_utxos,
                    "total_supply": stats.total_supply,
                    "latest_block_hash": latest_block.hash()?.to_hex(),
                    "latest_block_timestamp": latest_block.header.timestamp,
                    "difficulty": latest_block.header.difficulty,
                });
                println!("{}", serde_json::to_string_pretty(&overview)?);
            }
            _ => {
                println!("\n=== Blockchain Overview ===");
                println!("Height: {}", stats.height);
                println!("Total Blocks: {}", stats.total_blocks);
                println!("Total Transactions: {}", stats.total_transactions);
                println!("Total UTXOs: {}", stats.total_utxos);
                println!("Total Supply: {} satoshis ({:.8} BTC)", 
                    stats.total_supply, 
                    utils::satoshis_to_btc(stats.total_supply)
                );
                println!("Latest Block Hash: {}", latest_block.hash()?.to_hex());
                println!("Latest Block Timestamp: {} ({})", 
                    latest_block.header.timestamp,
                    utils::format_timestamp(latest_block.header.timestamp)
                );
                println!("Current Difficulty: {}", latest_block.header.difficulty);
                println!("==============================\n");
            }
        }
        
        Ok(())
    }
    
    /// Show block information
    fn show_block(&self, identifier: &str) -> Result<()> {
        let block = if let Ok(height) = identifier.parse::<u64>() {
            self.blockchain.get_block_by_height(height)?
        } else {
            let hash = utils::hex_to_hash(identifier)?;
            self.blockchain.get_block_by_hash(&hash)?
        };
        
        match self.config.output_format.as_str() {
            "json" => {
                let block_json = serde_json::json!({
                    "height": block.header.height,
                    "hash": block.hash()?.to_hex(),
                    "previous_hash": block.header.previous_hash.to_hex(),
                    "merkle_root": block.header.merkle_root.to_hex(),
                    "timestamp": block.header.timestamp,
                    "difficulty": block.header.difficulty,
                    "nonce": block.header.nonce,
                    "version": block.header.version,
                    "transaction_count": block.transactions.len(),
                    "transactions": block.transactions.iter().map(|tx| {
                        serde_json::json!({
                            "txid": tx.hash().unwrap().to_hex(),
                            "inputs": tx.inputs.len(),
                            "outputs": tx.outputs.len(),
                            "is_coinbase": tx.is_coinbase(),
                        })
                    }).collect::<Vec<_>>(),
                });
                println!("{}", serde_json::to_string_pretty(&block_json)?);
            }
            "detailed" => {
                self.show_block_detailed(&block)?;
            }
            _ => {
                self.show_block_table(&block)?;
            }
        }
        
        Ok(())
    }
    
    /// Show block in table format
    fn show_block_table(&self, block: &rust_blockchain::block::Block) -> Result<()> {
        println!("\n=== Block #{} ===", block.header.height);
        println!("Hash: {}", block.hash()?.to_hex());
        println!("Previous Hash: {}", block.header.previous_hash.to_hex());
        println!("Merkle Root: {}", block.header.merkle_root.to_hex());
        println!("Timestamp: {} ({})", 
            block.header.timestamp,
            utils::format_timestamp(block.header.timestamp)
        );
        println!("Difficulty: {}", block.header.difficulty);
        println!("Nonce: {}", block.header.nonce);
        println!("Version: {}", block.header.version);
        println!("Transaction Count: {}", block.transactions.len());
        
        if !block.transactions.is_empty() {
            println!("\nTransactions:");
            for (i, tx) in block.transactions.iter().enumerate() {
                let tx_type = if tx.is_coinbase() { "Coinbase" } else { "Regular" };
                println!("  {}: {} ({}) - {} inputs, {} outputs", 
                    i + 1,
                    tx.hash()?.to_hex(),
                    tx_type,
                    tx.inputs.len(),
                    tx.outputs.len()
                );
            }
        }
        
        println!("==================\n");
        Ok(())
    }
    
    /// Show block in detailed format
    fn show_block_detailed(&self, block: &rust_blockchain::block::Block) -> Result<()> {
        println!("\n=== Block #{} (Detailed) ===", block.header.height);
        println!("Hash: {}", block.hash()?.to_hex());
        println!("Previous Hash: {}", block.header.previous_hash.to_hex());
        println!("Merkle Root: {}", block.header.merkle_root.to_hex());
        println!("Timestamp: {} ({})", 
            block.header.timestamp,
            utils::format_timestamp(block.header.timestamp)
        );
        println!("Difficulty: {}", block.header.difficulty);
        println!("Nonce: {}", block.header.nonce);
        println!("Version: {}", block.header.version);
        println!("Size: {} bytes", utils::serialize(&block)?.len());
        
        let total_fees = block.transactions.iter()
            .skip(1) // Skip coinbase
            .map(|tx| tx.calculate_fee(&HashMap::new()).unwrap_or(0))
            .sum::<u64>();
        
        let total_output = block.transactions.iter()
            .flat_map(|tx| &tx.outputs)
            .map(|output| output.value)
            .sum::<u64>();
        
        println!("Total Output Value: {} satoshis ({:.8} BTC)", 
            total_output, 
            utils::satoshis_to_btc(total_output)
        );
        println!("Total Fees: {} satoshis ({:.8} BTC)", 
            total_fees, 
            utils::satoshis_to_btc(total_fees)
        );
        
        println!("\n--- Transactions ({}) ---", block.transactions.len());
        for (i, tx) in block.transactions.iter().enumerate() {
            self.show_transaction_summary(tx, i)?;
        }
        
        println!("===============================\n");
        Ok(())
    }
    
    /// Show transaction information
    fn show_transaction(&self, txid: &str) -> Result<()> {
        let tx_hash = utils::hex_to_hash(txid)?;
        
        // Find transaction in blockchain
        let mut found_tx = None;
        let mut block_height = None;
        
        for height in 0..=self.blockchain.get_height() {
            if let Ok(block) = self.blockchain.get_block_by_height(height) {
                for tx in &block.transactions {
                    if tx.hash()? == tx_hash {
                        found_tx = Some(tx.clone());
                        block_height = Some(height);
                        break;
                    }
                }
                if found_tx.is_some() {
                    break;
                }
            }
        }
        
        let tx = found_tx.ok_or_else(|| anyhow::anyhow!("Transaction not found: {}", txid))?;
        
        match self.config.output_format.as_str() {
            "json" => {
                let tx_json = serde_json::json!({
                    "txid": tx.hash()?.to_hex(),
                    "block_height": block_height,
                    "is_coinbase": tx.is_coinbase(),
                    "version": tx.version,
                    "lock_time": tx.lock_time,
                    "inputs": tx.inputs.iter().map(|input| {
                        serde_json::json!({
                            "previous_output": {
                                "txid": input.previous_output.txid.to_hex(),
                                "vout": input.previous_output.vout,
                            },
                            "script_sig": utils::bytes_to_hex(&input.script_sig),
                            "sequence": input.sequence,
                        })
                    }).collect::<Vec<_>>(),
                    "outputs": tx.outputs.iter().enumerate().map(|(i, output)| {
                        serde_json::json!({
                            "vout": i,
                            "value": output.value,
                            "script_pubkey": utils::bytes_to_hex(&output.script_pubkey),
                        })
                    }).collect::<Vec<_>>(),
                });
                println!("{}", serde_json::to_string_pretty(&tx_json)?);
            }
            _ => {
                self.show_transaction_detailed(&tx, block_height)?;
            }
        }
        
        Ok(())
    }
    
    /// Show transaction in detailed format
    fn show_transaction_detailed(&self, tx: &Transaction, block_height: Option<u64>) -> Result<()> {
        println!("\n=== Transaction ===");
        println!("TXID: {}", tx.hash()?.to_hex());
        if let Some(height) = block_height {
            println!("Block Height: {}", height);
        }
        println!("Type: {}", if tx.is_coinbase() { "Coinbase" } else { "Regular" });
        println!("Version: {}", tx.version);
        println!("Lock Time: {}", tx.lock_time);
        println!("Size: {} bytes", utils::serialize(tx)?.len());
        
        let total_input = if tx.is_coinbase() {
            0
        } else {
            // In a real implementation, you'd look up the input values
            0 // Placeholder
        };
        
        let total_output: u64 = tx.outputs.iter().map(|o| o.value).sum();
        let fee = if tx.is_coinbase() { 0 } else { total_input.saturating_sub(total_output) };
        
        println!("Total Input: {} satoshis ({:.8} BTC)", 
            total_input, 
            utils::satoshis_to_btc(total_input)
        );
        println!("Total Output: {} satoshis ({:.8} BTC)", 
            total_output, 
            utils::satoshis_to_btc(total_output)
        );
        println!("Fee: {} satoshis ({:.8} BTC)", 
            fee, 
            utils::satoshis_to_btc(fee)
        );
        
        println!("\n--- Inputs ({}) ---", tx.inputs.len());
        for (i, input) in tx.inputs.iter().enumerate() {
            if tx.is_coinbase() {
                println!("  {}: Coinbase ({})", i, utils::bytes_to_hex(&input.script_sig));
            } else {
                println!("  {}: {}:{}", i, input.previous_output.txid.to_hex(), input.previous_output.vout);
                println!("      Script: {}", utils::bytes_to_hex(&input.script_sig));
                println!("      Sequence: {}", input.sequence);
            }
        }
        
        println!("\n--- Outputs ({}) ---", tx.outputs.len());
        for (i, output) in tx.outputs.iter().enumerate() {
            println!("  {}: {} satoshis ({:.8} BTC)", 
                i, 
                output.value, 
                utils::satoshis_to_btc(output.value)
            );
            println!("      Script: {}", utils::bytes_to_hex(&output.script_pubkey));
        }
        
        println!("===================\n");
        Ok(())
    }
    
    /// Show transaction summary
    fn show_transaction_summary(&self, tx: &Transaction, index: usize) -> Result<()> {
        let total_output: u64 = tx.outputs.iter().map(|o| o.value).sum();
        let tx_type = if tx.is_coinbase() { "Coinbase" } else { "Regular" };
        
        println!("  {}: {} ({})", index + 1, tx.hash()?.to_hex(), tx_type);
        println!("      Inputs: {}, Outputs: {}", tx.inputs.len(), tx.outputs.len());
        println!("      Total Output: {} satoshis ({:.8} BTC)", 
            total_output, 
            utils::satoshis_to_btc(total_output)
        );
        
        Ok(())
    }
    
    /// Show address information
    fn show_address(&self, address: &str) -> Result<()> {
        if !utils::is_valid_address(address) {
            return Err(anyhow::anyhow!("Invalid address format: {}", address));
        }
        
        let utxo_set = self.blockchain.get_utxo_set();
        let balance = self.blockchain.get_balance(address)?;
        
        // Find UTXOs for this address
        let mut utxos = Vec::new();
        for (outpoint, utxo) in utxo_set {
            if utils::bytes_to_hex(&utxo.script_pubkey).contains(&address.replace("1", "")) {
                // Simplified address matching - in reality, you'd decode the script
                utxos.push((outpoint, utxo));
            }
        }
        
        // Find transaction history (simplified)
        let mut tx_history = Vec::new();
        for height in 0..=self.blockchain.get_height() {
            if let Ok(block) = self.blockchain.get_block_by_height(height) {
                for tx in &block.transactions {
                    let mut involved = false;
                    
                    // Check outputs
                    for output in &tx.outputs {
                        if utils::bytes_to_hex(&output.script_pubkey).contains(&address.replace("1", "")) {
                            involved = true;
                            break;
                        }
                    }
                    
                    if involved {
                        tx_history.push((height, tx.hash()?, tx.clone()));
                    }
                }
            }
        }
        
        match self.config.output_format.as_str() {
            "json" => {
                let address_json = serde_json::json!({
                    "address": address,
                    "balance": balance,
                    "balance_btc": utils::satoshis_to_btc(balance),
                    "utxo_count": utxos.len(),
                    "transaction_count": tx_history.len(),
                    "utxos": utxos.iter().map(|(outpoint, utxo)| {
                        serde_json::json!({
                            "txid": outpoint.txid.to_hex(),
                            "vout": outpoint.vout,
                            "value": utxo.value,
                            "script_pubkey": utils::bytes_to_hex(&utxo.script_pubkey),
                        })
                    }).collect::<Vec<_>>(),
                    "recent_transactions": tx_history.iter().take(10).map(|(height, txid, _)| {
                        serde_json::json!({
                            "block_height": height,
                            "txid": txid.to_hex(),
                        })
                    }).collect::<Vec<_>>(),
                });
                println!("{}", serde_json::to_string_pretty(&address_json)?);
            }
            _ => {
                println!("\n=== Address Information ===");
                println!("Address: {}", address);
                println!("Balance: {} satoshis ({:.8} BTC)", 
                    balance, 
                    utils::satoshis_to_btc(balance)
                );
                println!("UTXO Count: {}", utxos.len());
                println!("Transaction Count: {}", tx_history.len());
                
                if !utxos.is_empty() {
                    println!("\n--- Unspent Outputs ---");
                    for (outpoint, utxo) in utxos.iter().take(10) {
                        println!("  {}:{} - {} satoshis ({:.8} BTC)", 
                            outpoint.txid.to_hex(),
                            outpoint.vout,
                            utxo.value,
                            utils::satoshis_to_btc(utxo.value)
                        );
                    }
                    if utxos.len() > 10 {
                        println!("  ... and {} more", utxos.len() - 10);
                    }
                }
                
                if !tx_history.is_empty() {
                    println!("\n--- Recent Transactions ---");
                    for (height, txid, _) in tx_history.iter().take(10) {
                        println!("  Block {}: {}", height, txid.to_hex());
                    }
                    if tx_history.len() > 10 {
                        println!("  ... and {} more", tx_history.len() - 10);
                    }
                }
                
                println!("============================\n");
            }
        }
        
        Ok(())
    }
    
    /// List recent blocks
    fn list_blocks(&self, count: usize) -> Result<()> {
        let height = self.blockchain.get_height();
        let start_height = height.saturating_sub(count as u64 - 1);
        
        match self.config.output_format.as_str() {
            "json" => {
                let mut blocks = Vec::new();
                for h in start_height..=height {
                    if let Ok(block) = self.blockchain.get_block_by_height(h) {
                        blocks.push(serde_json::json!({
                            "height": h,
                            "hash": block.hash()?.to_hex(),
                            "timestamp": block.header.timestamp,
                            "transactions": block.transactions.len(),
                            "difficulty": block.header.difficulty,
                        }));
                    }
                }
                println!("{}", serde_json::to_string_pretty(&blocks)?);
            }
            _ => {
                println!("\n=== Recent Blocks ===");
                println!("{:<8} {:<64} {:<12} {:<5} {:<12}", 
                    "Height", "Hash", "Timestamp", "TXs", "Difficulty"
                );
                println!("{}", "-".repeat(110)
                );
                
                for h in start_height..=height {
                    if let Ok(block) = self.blockchain.get_block_by_height(h) {
                        println!("{:<8} {:<64} {:<12} {:<5} {:<12}", 
                            h,
                            block.hash()?.to_hex(),
                            utils::format_timestamp(block.header.timestamp),
                            block.transactions.len(),
                            block.header.difficulty
                        );
                    }
                }
                println!("=====================\n");
            }
        }
        
        Ok(())
    }
    
    /// Search for blocks or transactions
    fn search(&self, query: &str) -> Result<()> {
        println!("Searching for: {}\n", query);
        
        // Try as block height
        if let Ok(height) = query.parse::<u64>() {
            if height <= self.blockchain.get_height() {
                println!("Found block at height {}:", height);
                self.show_block(&height.to_string())?;
                return Ok(());
            }
        }
        
        // Try as hash (block or transaction)
        if query.len() == 64 && query.chars().all(|c| c.is_ascii_hexdigit()) {
            // Try as block hash
            if let Ok(hash) = utils::hex_to_hash(query) {
                if let Ok(_) = self.blockchain.get_block_by_hash(&hash) {
                    println!("Found block with hash {}:", query);
                    self.show_block(query)?;
                    return Ok(());
                }
            }
            
            // Try as transaction hash
            match self.show_transaction(query) {
                Ok(_) => {
                    println!("Found transaction with hash {}:", query);
                    return Ok(());
                }
                Err(_) => {}
            }
        }
        
        // Try as address
        if utils::is_valid_address(query) {
            println!("Found address {}:", query);
            self.show_address(query)?;
            return Ok(());
        }
        
        println!("No results found for: {}", query);
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let matches = Command::new("rust-blockchain-explorer")
        .version("1.0.0")
        .author("Rust Blockchain Team")
        .about("Blockchain explorer for Rust Blockchain")
        .arg(
            Arg::new("data-dir")
                .long("data-dir")
                .value_name("DIR")
                .help("Data directory for blockchain storage")
                .default_value("./data"),
        )
        .arg(
            Arg::new("format")
                .long("format")
                .value_name("FORMAT")
                .help("Output format (table, json, detailed)")
                .default_value("table"),
        )
        .arg(
            Arg::new("log-level")
                .long("log-level")
                .value_name("LEVEL")
                .help("Log level (trace, debug, info, warn, error)")
                .default_value("warn"),
        )
        .subcommand(
            SubCommand::with_name("overview")
                .about("Show blockchain overview")
        )
        .subcommand(
            SubCommand::with_name("block")
                .about("Show block information")
                .arg(
                    Arg::new("identifier")
                        .help("Block height or hash")
                        .required(true)
                        .index(1),
                )
        )
        .subcommand(
            SubCommand::with_name("transaction")
                .about("Show transaction information")
                .arg(
                    Arg::new("txid")
                        .help("Transaction ID")
                        .required(true)
                        .index(1),
                )
        )
        .subcommand(
            SubCommand::with_name("address")
                .about("Show address information")
                .arg(
                    Arg::new("address")
                        .help("Address to query")
                        .required(true)
                        .index(1),
                )
        )
        .subcommand(
            SubCommand::with_name("blocks")
                .about("List recent blocks")
                .arg(
                    Arg::new("count")
                        .long("count")
                        .value_name("COUNT")
                        .help("Number of blocks to show")
                        .default_value("10"),
                )
        )
        .subcommand(
            SubCommand::with_name("search")
                .about("Search for blocks, transactions, or addresses")
                .arg(
                    Arg::new("query")
                        .help("Search query (height, hash, or address)")
                        .required(true)
                        .index(1),
                )
        )
        .get_matches();
    
    // Initialize logging
    let log_level = matches.get_one::<String>("log-level").unwrap();
    let filter = match log_level.as_str() {
        "trace" => tracing::Level::TRACE,
        "debug" => tracing::Level::DEBUG,
        "info" => tracing::Level::INFO,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        _ => tracing::Level::WARN,
    };
    
    tracing_subscriber::fmt()
        .with_max_level(filter)
        .init();
    
    // Parse configuration
    let mut config = ExplorerConfig::default();
    config.data_dir = PathBuf::from(matches.get_one::<String>("data-dir").unwrap());
    config.output_format = matches.get_one::<String>("format").unwrap().to_string();
    config.log_level = log_level.clone();
    
    // Validate output format
    match config.output_format.as_str() {
        "table" | "json" | "detailed" => {},
        _ => {
            return Err(anyhow::anyhow!(
                "Invalid output format: {}. Must be 'table', 'json', or 'detailed'",
                config.output_format
            ));
        }
    }
    
    // Create explorer
    let explorer = BlockchainExplorer::new(config)?;
    
    // Handle subcommands
    match matches.subcommand() {
        Some(("overview", _)) => {
            explorer.show_overview()?;
        }
        Some(("block", sub_matches)) => {
            let identifier = sub_matches.get_one::<String>("identifier").unwrap();
            explorer.show_block(identifier)?;
        }
        Some(("transaction", sub_matches)) => {
            let txid = sub_matches.get_one::<String>("txid").unwrap();
            explorer.show_transaction(txid)?;
        }
        Some(("address", sub_matches)) => {
            let address = sub_matches.get_one::<String>("address").unwrap();
            explorer.show_address(address)?;
        }
        Some(("blocks", sub_matches)) => {
            let count: usize = sub_matches.get_one::<String>("count").unwrap().parse()?;
            explorer.list_blocks(count)?;
        }
        Some(("search", sub_matches)) => {
            let query = sub_matches.get_one::<String>("query").unwrap();
            explorer.search(query)?;
        }
        _ => {
            // Default to overview
            explorer.show_overview()?;
        }
    }
    
    Ok(())
}