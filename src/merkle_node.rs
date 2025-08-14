use crate::config::ARITY;
use crate::hash_algo::generate_hash;
use crate::transaction::Transaction;

pub struct MerkleNode {
    pub hash_val: String,
    pub child: Vec<MerkleNode>,
    pub txn: bool,
}

impl MerkleNode {
    pub fn new(child: Vec<MerkleNode>, txn_flag: bool) -> Self {
        let hash_val = if txn_flag {
            if let Some(first) = child.first() {
                first.hash_val.clone()
            } else {
                String::new()
            }
        } else {
            let mut all_hash_val = String::new();
            child.iter().for_each(|c| {
                all_hash_val.push_str(&c.hash_val);
            });

            let missing = ARITY - child.len();
            if missing > 0 {
                if let Some(last) = child.last() {
                    (0..missing).for_each(|_| all_hash_val.push_str(&last.hash_val));
                }
            }
            generate_hash(&all_hash_val)
        };

        Self {
            hash_val,
            child,
            txn: txn_flag,
        }
    }

    pub fn from_transaction(txn: &Transaction) -> Self {
        Self {
            hash_val: txn.hash_val.clone(),
            child: vec![],
            txn: true,
        }
    }
}
