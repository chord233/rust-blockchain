//! Blockchain CLI tool
//!
//! Command-line interface for interacting with the blockchain,
//! managing wallets, sending transactions, and querying blockchain data.

use anyhow::Result;
use clap::{Arg, Command, ArgMatches};
use rust_blockchain::{
    blockchain::Blockchain,
    crypto::{Hash, KeyPair},
    storage::Storage,
    transaction::{Transaction, TxInput, TxOutput},
    utils,
    wallet::WalletManager,
};
use std::path::PathBuf;
use tracing::{error, info};
use tracing_subscriber;

/// CLI configuration
#[derive(Debug, Clone)]
struct CliConfig {
    /// Data directory
    data_dir: PathBuf,
    /// Log level
    log_level: String,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data"),
            log_level: "info".to_string(),
        }
    }
}

/// CLI application
struct Cli {
    config: CliConfig,
}

impl Cli {
    fn new(config: CliConfig) -> Self {
        Self { config }
    }

    /// Execute CLI command
    async fn execute(&self, matches: &ArgMatches) -> Result<()> {
        match matches.subcommand() {
            Some(("wallet", sub_matches)) => {
                self.handle_wallet_command(sub_matches).await
            }
            Some(("blockchain", sub_matches)) => {
                self.handle_blockchain_command(sub_matches).await
            }
            Some(("transaction", sub_matches)) => {
                self.handle_transaction_command(sub_matches).await
            }
            Some(("address", sub_matches)) => {
                self.handle_address_command(sub_matches).await
            }
            _ => {
                println!("No command specified. Use --help for usage information.");
                Ok(())
            }
        }
    }

    /// Handle wallet commands
    async fn handle_wallet_command(&self, matches: &ArgMatches) -> Result<()> {
        let wallet_path = self.config.data_dir.join("wallets");
        let mut wallet_manager = WalletManager::new(&wallet_path)?;

        match matches.subcommand() {
            Some(("create", sub_matches)) => {
                let name = sub_matches.get_one::<String>("name").unwrap();
                let wallet = wallet_manager.create_wallet(name)?;
                
                println!("Created wallet: {}", name);
                println!("Address: {}", wallet.address);
                println!("Public Key: {}", hex::encode(&wallet.public_key));
                println!("\n⚠️  IMPORTANT: Save your private key securely!");
                println!("Private Key: {}", hex::encode(&wallet.private_key));
            }
            Some(("import", sub_matches)) => {
                let name = sub_matches.get_one::<String>("name").unwrap();
                let private_key_hex = sub_matches.get_one::<String>("private-key").unwrap();
                
                let private_key = hex::decode(private_key_hex)
                    .map_err(|_| anyhow::anyhow!("Invalid private key format"))?;
                
                let wallet = wallet_manager.import_wallet(name, &private_key)?;
                
                println!("Imported wallet: {}", name);
                println!("Address: {}", wallet.address);
            }
            Some(("list", _)) => {
                let wallets = wallet_manager.list_wallets();
                
                if wallets.is_empty() {
                    println!("No wallets found.");
                } else {
                    println!("Wallets:");
                    for wallet in wallets {
                        println!("  {} - {}", wallet.name, wallet.address);
                    }
                }
            }
            Some(("balance", sub_matches)) => {
                let name = sub_matches.get_one::<String>("name").unwrap();
                let wallet = wallet_manager.get_wallet(name)
                    .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found", name))?;
                
                // Load blockchain
                let storage_path = self.config.data_dir.join("blockchain");
                let storage = Storage::new(&storage_path)?;
                let blockchain = Blockchain::load(storage)?;
                
                let balance = blockchain.get_balance(&wallet.address)?;
                
                println!("Wallet: {}", name);
                println!("Address: {}", wallet.address);
                println!("Balance: {} satoshis ({:.8} BTC)", balance, utils::satoshis_to_btc(balance));
            }
            Some(("delete", sub_matches)) => {
                let name = sub_matches.get_one::<String>("name").unwrap();
                
                print!("Are you sure you want to delete wallet '{}'? (y/N): ", name);
                use std::io::{self, Write};
                io::stdout().flush()?;
                
                let mut input = String::new();
                io::stdin().read_line(&mut input)?;
                
                if input.trim().to_lowercase() == "y" {
                    wallet_manager.delete_wallet(name)?;
                    println!("Wallet '{}' deleted.", name);
                } else {
                    println!("Operation cancelled.");
                }
            }
            _ => {
                println!("Unknown wallet command. Use --help for usage information.");
            }
        }
        
        Ok(())
    }

    /// Handle blockchain commands
    async fn handle_blockchain_command(&self, matches: &ArgMatches) -> Result<()> {
        let storage_path = self.config.data_dir.join("blockchain");
        let storage = Storage::new(&storage_path)?;
        
        if storage.is_empty()? {
            println!("Blockchain not found. Initialize a new blockchain first.");
            return Ok(());
        }
        
        let blockchain = Blockchain::load(storage)?;

        match matches.subcommand() {
            Some(("info", _)) => {
                let stats = blockchain.get_stats();
                let latest_block = blockchain.get_latest_block()?;
                
                println!("Blockchain Information:");
                println!("  Height: {}", stats.height);
                println!("  Total Blocks: {}", stats.total_blocks);
                println!("  Total Transactions: {}", stats.total_transactions);
                println!("  Total Supply: {} satoshis ({:.8} BTC)", 
                    stats.total_supply, utils::satoshis_to_btc(stats.total_supply));
                println!("  Latest Block Hash: {}", latest_block.hash()?.to_hex());
                println!("  Latest Block Time: {}", 
                    chrono::DateTime::from_timestamp(latest_block.header.timestamp as i64, 0)
                        .unwrap_or_default()
                        .format("%Y-%m-%d %H:%M:%S UTC"));
                println!("  Difficulty: {}", latest_block.header.difficulty);
            }
            Some(("block", sub_matches)) => {
                if let Some(height_str) = sub_matches.get_one::<String>("height") {
                    let height: u64 = height_str.parse()
                        .map_err(|_| anyhow::anyhow!("Invalid block height"))?;
                    
                    if let Some(block) = blockchain.get_block_by_height(height)? {
                        self.print_block_info(&block)?;
                    } else {
                        println!("Block at height {} not found.", height);
                    }
                } else if let Some(hash_str) = sub_matches.get_one::<String>("hash") {
                    let hash = Hash::from_hex(hash_str)
                        .map_err(|_| anyhow::anyhow!("Invalid block hash"))?;
                    
                    if let Some(block) = blockchain.get_block_by_hash(&hash)? {
                        self.print_block_info(&block)?;
                    } else {
                        println!("Block with hash {} not found.", hash_str);
                    }
                } else {
                    println!("Please specify either --height or --hash");
                }
            }
            Some(("list", sub_matches)) => {
                let count: usize = sub_matches.get_one::<String>("count")
                    .unwrap_or(&"10".to_string())
                    .parse()
                    .unwrap_or(10);
                
                let latest_height = blockchain.get_height();
                let start_height = latest_height.saturating_sub(count as u64 - 1);
                
                println!("Latest {} blocks:", count);
                for height in start_height..=latest_height {
                    if let Some(block) = blockchain.get_block_by_height(height)? {
                        let timestamp = chrono::DateTime::from_timestamp(block.header.timestamp as i64, 0)
                            .unwrap_or_default()
                            .format("%Y-%m-%d %H:%M:%S");
                        
                        println!("  {} | {} | {} txs | {}", 
                            height,
                            block.hash()?.to_hex()[..16].to_string() + "...",
                            block.transactions.len(),
                            timestamp
                        );
                    }
                }
            }
            Some(("validate", _)) => {
                println!("Validating blockchain...");
                match blockchain.validate() {
                    Ok(()) => println!("✅ Blockchain is valid!"),
                    Err(e) => println!("❌ Blockchain validation failed: {}", e),
                }
            }
            _ => {
                println!("Unknown blockchain command. Use --help for usage information.");
            }
        }
        
        Ok(())
    }

    /// Handle transaction commands
    async fn handle_transaction_command(&self, matches: &ArgMatches) -> Result<()> {
        match matches.subcommand() {
            Some(("send", sub_matches)) => {
                let from = sub_matches.get_one::<String>("from").unwrap();
                let to = sub_matches.get_one::<String>("to").unwrap();
                let amount_str = sub_matches.get_one::<String>("amount").unwrap();
                let fee_str = sub_matches.get_one::<String>("fee").unwrap_or(&"1000".to_string());
                
                let amount: f64 = amount_str.parse()
                    .map_err(|_| anyhow::anyhow!("Invalid amount"))?;
                let fee: u64 = fee_str.parse()
                    .map_err(|_| anyhow::anyhow!("Invalid fee"))?;
                
                let amount_satoshis = utils::btc_to_satoshis(amount);
                
                // Load wallet
                let wallet_path = self.config.data_dir.join("wallets");
                let wallet_manager = WalletManager::new(&wallet_path)?;
                let wallet = wallet_manager.get_wallet(from)
                    .ok_or_else(|| anyhow::anyhow!("Wallet '{}' not found", from))?;
                
                // Load blockchain
                let storage_path = self.config.data_dir.join("blockchain");
                let storage = Storage::new(&storage_path)?;
                let blockchain = Blockchain::load(storage)?;
                
                // Create transaction
                let transaction = wallet_manager.create_transaction(
                    from,
                    to,
                    amount_satoshis,
                    fee,
                    blockchain.get_utxo_set(),
                )?;
                
                println!("Transaction created:");
                println!("  Hash: {}", transaction.hash()?.to_hex());
                println!("  From: {} ({})", from, wallet.address);
                println!("  To: {}", to);
                println!("  Amount: {} satoshis ({:.8} BTC)", amount_satoshis, amount);
                println!("  Fee: {} satoshis", fee);
                println!("  Size: {} bytes", transaction.size()?);
                
                // TODO: Broadcast transaction to network
                println!("\n⚠️  Transaction created but not broadcasted. Implement network broadcasting.");
            }
            Some(("history", sub_matches)) => {
                let address = sub_matches.get_one::<String>("address").unwrap();
                
                // Load blockchain
                let storage_path = self.config.data_dir.join("blockchain");
                let storage = Storage::new(&storage_path)?;
                let blockchain = Blockchain::load(storage)?;
                
                println!("Transaction history for address: {}", address);
                
                // This is a simplified implementation
                // In a real system, you'd have an index for address transactions
                let mut found_transactions = 0;
                
                for height in 0..=blockchain.get_height() {
                    if let Some(block) = blockchain.get_block_by_height(height)? {
                        for (tx_index, tx) in block.transactions.iter().enumerate() {
                            let mut is_relevant = false;
                            let mut tx_type = "";
                            let mut amount = 0u64;
                            
                            // Check inputs
                            for input in &tx.inputs {
                                if let Some(prev_tx) = self.find_transaction_in_blockchain(&blockchain, &input.prev_tx_hash)? {
                                    if let Some(prev_output) = prev_tx.outputs.get(input.output_index as usize) {
                                        if prev_output.address == *address {
                                            is_relevant = true;
                                            tx_type = "sent";
                                            amount = prev_output.value;
                                            break;
                                        }
                                    }
                                }
                            }
                            
                            // Check outputs
                            for output in &tx.outputs {
                                if output.address == *address {
                                    is_relevant = true;
                                    if tx_type.is_empty() {
                                        tx_type = "received";
                                    }
                                    amount = output.value;
                                    break;
                                }
                            }
                            
                            if is_relevant {
                                let timestamp = chrono::DateTime::from_timestamp(block.header.timestamp as i64, 0)
                                    .unwrap_or_default()
                                    .format("%Y-%m-%d %H:%M:%S");
                                
                                println!("  {} | Block {} | {} | {} satoshis | {}",
                                    timestamp,
                                    height,
                                    tx_type,
                                    amount,
                                    tx.hash()?.to_hex()[..16].to_string() + "..."
                                );
                                
                                found_transactions += 1;
                            }
                        }
                    }
                }
                
                if found_transactions == 0 {
                    println!("  No transactions found for this address.");
                }
            }
            _ => {
                println!("Unknown transaction command. Use --help for usage information.");
            }
        }
        
        Ok(())
    }

    /// Handle address commands
    async fn handle_address_command(&self, matches: &ArgMatches) -> Result<()> {
        match matches.subcommand() {
            Some(("generate", _)) => {
                let keypair = KeyPair::new();
                let address = keypair.address();
                
                println!("Generated new address:");
                println!("  Address: {}", address);
                println!("  Public Key: {}", hex::encode(keypair.public_key()));
                println!("  Private Key: {}", hex::encode(keypair.private_key()));
                println!("\n⚠️  IMPORTANT: Save your private key securely!");
            }
            Some(("validate", sub_matches)) => {
                let address = sub_matches.get_one::<String>("address").unwrap();
                
                if utils::is_valid_address(address) {
                    println!("✅ Address '{}' is valid", address);
                } else {
                    println!("❌ Address '{}' is invalid", address);
                }
            }
            _ => {
                println!("Unknown address command. Use --help for usage information.");
            }
        }
        
        Ok(())
    }

    /// Print detailed block information
    fn print_block_info(&self, block: &rust_blockchain::block::Block) -> Result<()> {
        let timestamp = chrono::DateTime::from_timestamp(block.header.timestamp as i64, 0)
            .unwrap_or_default()
            .format("%Y-%m-%d %H:%M:%S UTC");
        
        println!("Block Information:");
        println!("  Hash: {}", block.hash()?.to_hex());
        println!("  Height: {}", block.header.height);
        println!("  Version: {}", block.header.version);
        println!("  Previous Hash: {}", block.header.prev_hash.to_hex());
        println!("  Merkle Root: {}", block.header.merkle_root.to_hex());
        println!("  Timestamp: {} ({})", block.header.timestamp, timestamp);
        println!("  Difficulty: {}", block.header.difficulty);
        println!("  Nonce: {}", block.header.nonce);
        println!("  Transactions: {}", block.transactions.len());
        println!("  Size: {} bytes", block.size()?);
        
        if !block.transactions.is_empty() {
            println!("\n  Transactions:");
            for (i, tx) in block.transactions.iter().enumerate() {
                let tx_type = if tx.is_coinbase() { "coinbase" } else { "regular" };
                println!("    {} | {} | {} | {} inputs, {} outputs",
                    i,
                    tx.hash()?.to_hex()[..16].to_string() + "...",
                    tx_type,
                    tx.inputs.len(),
                    tx.outputs.len()
                );
            }
        }
        
        Ok(())
    }

    /// Find a transaction in the blockchain by hash
    fn find_transaction_in_blockchain(
        &self,
        blockchain: &Blockchain,
        tx_hash: &Hash,
    ) -> Result<Option<Transaction>> {
        for height in 0..=blockchain.get_height() {
            if let Some(block) = blockchain.get_block_by_height(height)? {
                for tx in &block.transactions {
                    if tx.hash()? == *tx_hash {
                        return Ok(Some(tx.clone()));
                    }
                }
            }
        }
        Ok(None)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let matches = Command::new("rust-blockchain-cli")
        .version("1.0.0")
        .author("Rust Blockchain Team")
        .about("Command-line interface for Rust Blockchain")
        .arg(
            Arg::new("data-dir")
                .long("data-dir")
                .value_name("DIR")
                .help("Data directory for blockchain storage")
                .default_value("./data"),
        )
        .arg(
            Arg::new("log-level")
                .long("log-level")
                .value_name("LEVEL")
                .help("Log level (trace, debug, info, warn, error)")
                .default_value("info"),
        )
        .subcommand(
            Command::new("wallet")
                .about("Wallet management")
                .subcommand(
                    Command::new("create")
                        .about("Create a new wallet")
                        .arg(
                            Arg::new("name")
                                .help("Wallet name")
                                .required(true)
                                .index(1),
                        ),
                )
                .subcommand(
                    Command::new("import")
                        .about("Import a wallet from private key")
                        .arg(
                            Arg::new("name")
                                .help("Wallet name")
                                .required(true)
                                .index(1),
                        )
                        .arg(
                            Arg::new("private-key")
                                .help("Private key in hex format")
                                .required(true)
                                .index(2),
                        ),
                )
                .subcommand(Command::new("list").about("List all wallets"))
                .subcommand(
                    Command::new("balance")
                        .about("Get wallet balance")
                        .arg(
                            Arg::new("name")
                                .help("Wallet name")
                                .required(true)
                                .index(1),
                        ),
                )
                .subcommand(
                    Command::new("delete")
                        .about("Delete a wallet")
                        .arg(
                            Arg::new("name")
                                .help("Wallet name")
                                .required(true)
                                .index(1),
                        ),
                ),
        )
        .subcommand(
            Command::new("blockchain")
                .about("Blockchain operations")
                .subcommand(Command::new("info").about("Show blockchain information"))
                .subcommand(
                    Command::new("block")
                        .about("Get block information")
                        .arg(
                            Arg::new("height")
                                .long("height")
                                .value_name("HEIGHT")
                                .help("Block height")
                                .conflicts_with("hash"),
                        )
                        .arg(
                            Arg::new("hash")
                                .long("hash")
                                .value_name("HASH")
                                .help("Block hash")
                                .conflicts_with("height"),
                        ),
                )
                .subcommand(
                    Command::new("list")
                        .about("List recent blocks")
                        .arg(
                            Arg::new("count")
                                .long("count")
                                .value_name("COUNT")
                                .help("Number of blocks to show")
                                .default_value("10"),
                        ),
                )
                .subcommand(Command::new("validate").about("Validate the entire blockchain")),
        )
        .subcommand(
            Command::new("transaction")
                .about("Transaction operations")
                .subcommand(
                    Command::new("send")
                        .about("Send a transaction")
                        .arg(
                            Arg::new("from")
                                .long("from")
                                .value_name("WALLET")
                                .help("Source wallet name")
                                .required(true),
                        )
                        .arg(
                            Arg::new("to")
                                .long("to")
                                .value_name("ADDRESS")
                                .help("Destination address")
                                .required(true),
                        )
                        .arg(
                            Arg::new("amount")
                                .long("amount")
                                .value_name("BTC")
                                .help("Amount in BTC")
                                .required(true),
                        )
                        .arg(
                            Arg::new("fee")
                                .long("fee")
                                .value_name("SATOSHIS")
                                .help("Transaction fee in satoshis")
                                .default_value("1000"),
                        ),
                )
                .subcommand(
                    Command::new("history")
                        .about("Show transaction history for an address")
                        .arg(
                            Arg::new("address")
                                .help("Address to query")
                                .required(true)
                                .index(1),
                        ),
                ),
        )
        .subcommand(
            Command::new("address")
                .about("Address operations")
                .subcommand(Command::new("generate").about("Generate a new address"))
                .subcommand(
                    Command::new("validate")
                        .about("Validate an address")
                        .arg(
                            Arg::new("address")
                                .help("Address to validate")
                                .required(true)
                                .index(1),
                        ),
                ),
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
        _ => tracing::Level::INFO,
    };

    tracing_subscriber::fmt()
        .with_max_level(filter)
        .init();

    // Parse configuration
    let mut config = CliConfig::default();
    config.data_dir = PathBuf::from(matches.get_one::<String>("data-dir").unwrap());
    config.log_level = log_level.clone();

    // Create data directory if it doesn't exist
    std::fs::create_dir_all(&config.data_dir)?;

    // Create and execute CLI
    let cli = Cli::new(config);
    cli.execute(&matches).await?;

    Ok(())
}