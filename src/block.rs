use std::sync::{Arc, Mutex};

use crate::config::ARITY;
use crate::hash_algo::generate_hash;
use crate::merkle_node::MerkleNode;
use crate::transaction::Transaction;

// use std::{cell::RefCell, rc::Rc};

type BlockPtr = Option<Arc<Mutex<Block>>>;

#[derive(Clone)]
pub struct Block {
    pub prev_block: BlockPtr,
    pub prev_block_hash: String,
    pub txn_list: Vec<Transaction>,
    pub txn_size: usize,
    pub merkle_tree_root: MerkleNode,
    pub nonce: u64,
    pub hash_val: String,
}

impl Block {
    pub fn new(
        prev_block: BlockPtr,
        root: MerkleNode,
        nonce: u64,
        txn_list: Vec<Transaction>,
    ) -> Self {
        let prev_block_hash = if let Some(ref prev) = prev_block {
            prev.lock().unwrap().hash_val.to_string()
        } else {
            String::new()
        };

        let txn_size = txn_list.len();
        let mut all_hash = String::new();
        all_hash.push_str(&prev_block_hash);
        all_hash.push_str(&nonce.to_string());
        all_hash.push_str(&txn_size.to_string());
        all_hash.push_str(&root.hash_val);

        let hash_val = generate_hash(&all_hash);

        Self {
            prev_block,
            prev_block_hash,
            txn_list,
            txn_size,
            merkle_tree_root: root,
            nonce,
            hash_val,
        }
    }

    pub fn get_size(&self) -> usize {
        let mut total_size = 0;
        total_size += self.prev_block_hash.len();
        total_size += std::mem::size_of_val(&self.nonce);
        total_size += self.hash_val.len();

        self.txn_list
            .iter()
            .for_each(|txn| total_size += txn.get_size());

        // **FIXED**: The Merkle tree size calculation now correctly uses the actual
        // number of transactions in the block, not a hardcoded value like 15.
        let mut nodes_merkle_tree = self.txn_size;
        let mut n = self.txn_size;
        let arity = ARITY;
        while n > 1 {
            let next_level_nodes = (n + arity - 1) / arity;
            nodes_merkle_tree += next_level_nodes;
            n = next_level_nodes;
        }
        total_size += nodes_merkle_tree * self.merkle_tree_root.hash_val.len();

        total_size
    }
}
