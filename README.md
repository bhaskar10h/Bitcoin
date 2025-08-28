 # Bitcoin in Rust

 This repository contains a Rust-based implementation of a simplified Bitcoin-like blockchain system,
 inspired by the work of [RajputGarima/Bitcoin](https://github.com/RajputGarima/Bitcoin).
 The project simulates a network of nodes that perform transactions, create blocks,
 and maintain a blockchain with proof-of-work consensus,
 UTXO (Unspent Transaction Output) tracking, and Merkle trees.

 ## Features
 - [x] **Node Network**: Multiple nodes running concurrently, each with multiple wallet addresses using RSA cryptography.
 - [x] **Blockchain**: Implements a blockchain with genesis block creation and block linking using hashes.
 - [x] **Transactions**: Supports transaction creation, validation, and UTXO management with digital signatures.
 - [x] **Proof of Work**: Simple proof-of-work mechanism to secure the blockchain.
 - [x] **Merkle Trees**: Efficient data structure for transaction verification.
 - [x] **Console Output**: Pretty-printed tables for transaction and UTXO states.

 ## Prerequisites
 - **Rust**: Ensure you have Rust installed. Install it via [rustup](https://rustup.rs/).
 - **Dependencies**: The project uses external crates. Install them with `cargo build` after cloning.

 ## Installation
 1. Clone the repository:
    ```bash
    git clone https://github.com/bhaskar10h/bitcoin-rust.git
    cd bitcoin-rust
    ```
 2. Build the project:
    ```bash
    cargo build --release
    ```
 3. Run the project:
    ```bash
    cargo run --release
    ```

 ## Usage
 - The program simulates a network of 10 nodes (configurable via `config.rs`).
 - Upon running, it creates a genesis block and initializes nodes with 1000 bitcoins each (an estimation).
 - Nodes periodically attempt to create transactions (5% chance per second) and mine blocks every 15 seconds.
 - Output includes transaction tables, UTXO states, and block details printed to the console.

 ## Project Structure
 - `.cargo/config.toml`: suppress `COMPILER` warnings.
 - `src/main.rs`: Entry point of the application.
 - `src/block.rs`: Defines the `Block` struct and its methods.
 - `src/blockchain.rs`: Implements the `BlockChain` struct.
 - `src/bitcoinscript.rs`: Handles script execution for transaction validation.
 - `src/config.rs`: Configuration constants (e.g., number of nodes, nonce size).
 - `src/hash_algo.rs`: Hashing utilities using SHA-256.
 - `src/merkle_node.rs`: Merkle tree node implementation.
 - `src/node.rs`: Core logic for node behavior (transaction creation, block mining).
 - `src/transaction.rs`: Defines the `Transaction` struct and validation logic.

 ## Fixes
 - Still fixing the errors
 - Will optimise the code, to make it faster
 - Naming convention needs to be followed 

 ## Contributing
 Feel free to fork this repository and submit pull requests.
 Issues and feature requests are welcome at [https://github.com/bhaskar10h/Bitcoin/issues](https://github.com/bhaskar10h/Bitcoin/issues).

 ## Acknowledgments
 - Inspired by [RajputGarima/Bitcoin](https://github.com/RajputGarima/Bitcoin).
 - Thanks to the Rust community for excellent tools and libraries.

 ## Previous Branch
 I had a conflict with my previous branch due to an unused account being configured,
 So, I deleted it and rebranded this repo with the original author' user.name 
