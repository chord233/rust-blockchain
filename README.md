# Rust Blockchain

A complete blockchain implementation written in Rust, featuring a modular architecture with consensus mechanisms, networking, and multiple CLI tools.

## Features

- **Complete Blockchain Implementation**: Full blockchain with blocks, transactions, and merkle trees
- **Proof of Work Consensus**: Configurable difficulty adjustment and mining
- **P2P Networking**: Peer-to-peer communication with node discovery
- **Wallet Management**: HD wallet with key generation and transaction signing
- **Memory Pool**: Transaction pool with validation and management
- **Storage Layer**: Persistent storage with RocksDB backend
- **CLI Tools**: Multiple command-line tools for different use cases

## Architecture

The project is organized into several core modules:

- `blockchain`: Core blockchain logic and validation
- `block`: Block structure and operations
- `transaction`: Transaction handling and validation
- `consensus`: Proof of Work consensus implementation
- `network`: P2P networking and peer management
- `wallet`: HD wallet and cryptographic operations
- `mempool`: Transaction pool management
- `storage`: Persistent data storage
- `utils`: Utility functions and helpers

## CLI Tools

The project includes four specialized CLI tools:

### 1. Node (`node`)
Runs a full blockchain node with P2P networking and mining capabilities.

```bash
cargo run --bin node -- --data-dir ./data --listen 0.0.0.0:8333 --mining
```

### 2. CLI (`cli`)
Interactive command-line interface for wallet and blockchain operations.

```bash
# Create a new wallet
cargo run --bin cli -- wallet create --name my_wallet

# Send a transaction
cargo run --bin cli -- transaction send --from <address> --to <address> --amount 10.0

# Check balance
cargo run --bin cli -- wallet balance --address <address>
```

### 3. Miner (`miner`)
Dedicated mining tool with multi-threading support.

```bash
cargo run --bin miner -- --data-dir ./data --address <mining_address> --threads 4
```

### 4. Explorer (`explorer`)
Blockchain explorer for viewing blocks, transactions, and addresses.

```bash
# View blockchain overview
cargo run --bin explorer -- overview

# View specific block
cargo run --bin explorer -- block --hash <block_hash>

# View transaction
cargo run --bin explorer -- transaction --hash <tx_hash>
```

## Installation

### Prerequisites

- Rust 1.70+ (install from [rustup.rs](https://rustup.rs/))
- Git

### Build from Source

```bash
# Clone the repository
git clone https://github.com/chord233/rust-blockchain.git
cd rust-blockchain

# Build the project
cargo build --release

# Run tests
cargo test
```

## Quick Start

1. **Start a node**:
   ```bash
   cargo run --bin node -- --data-dir ./node1 --listen 0.0.0.0:8333
   ```

2. **Create a wallet** (in another terminal):
   ```bash
   cargo run --bin cli -- wallet create --name alice
   ```

3. **Start mining**:
   ```bash
   cargo run --bin miner -- --data-dir ./node1 --address <alice_address>
   ```

4. **Explore the blockchain**:
   ```bash
   cargo run --bin explorer -- overview
   ```

## Configuration

### Node Configuration

- `--data-dir`: Data directory for blockchain storage
- `--listen`: Network listening address
- `--bootstrap`: Bootstrap nodes for network discovery
- `--mining`: Enable mining
- `--rpc-port`: RPC server port
- `--log-level`: Logging level (trace, debug, info, warn, error)

### Mining Configuration

- `--threads`: Number of mining threads
- `--intensity`: Mining intensity (1-10)
- `--max-time`: Maximum mining time per block
- `--max-transactions`: Maximum transactions per block

## Development

### Project Structure

```
src/
├── bin/                 # CLI applications
│   ├── node.rs         # Full node
│   ├── cli.rs          # Interactive CLI
│   ├── miner.rs        # Mining tool
│   └── explorer.rs     # Blockchain explorer
├── block.rs            # Block implementation
├── blockchain.rs       # Blockchain logic
├── consensus.rs        # Consensus mechanisms
├── crypto.rs           # Cryptographic functions
├── error.rs            # Error handling
├── lib.rs              # Library root
├── mempool.rs          # Transaction pool
├── network.rs          # P2P networking
├── storage.rs          # Data persistence
├── transaction.rs      # Transaction handling
├── utils.rs            # Utility functions
└── wallet.rs           # Wallet management
```

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test module
cargo test blockchain

# Run with output
cargo test -- --nocapture
```

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by Bitcoin and Ethereum implementations
- Built with the Rust ecosystem
- Uses RocksDB for efficient storage
- Implements industry-standard cryptographic primitives

## Contact

- GitHub: [@chord233](https://github.com/chord233)
- Email: chord244@gmail.com
- Twitter: [@chord244](https://twitter.com/chord244)
- LinkedIn: [chord233](https://linkedin.com/in/chord233)

---

**Note**: This is an educational blockchain implementation. Do not use in production environments without proper security audits.