use crate::{config::ARITY, hash_algo::generate_hash, transaction::Transaction};

#[derive(Clone)]
pub struct MerkleNode {
    pub hash_val: String,
    pub child: Vec<Self>,
    pub is_transaction: bool,
}

impl MerkleNode {
    pub fn new(child: Vec<MerkleNode>, is_transaction: bool) -> Self {
        let hash_val = if is_transaction {
            child
                .first()
                .map_or(String::new(), |node| node.hash_val.clone())
        } else {
            let mut all_hash = String::new();
            child.iter().for_each(|ch| all_hash.push_str(&ch.hash_val));

            let missing = ARITY - child.len();
            if missing > 0 {
                if let Some(last) = child.last() {
                    (0..missing).for_each(|_| all_hash.push_str(&last.hash_val));
                }
            }
            generate_hash(&all_hash)
        };

        return Self {
            hash_val,
            child,
            is_transaction,
        };
    }

    pub fn from_transaction(transaction: &Transaction) -> Self {
        Self {
            hash_val: transaction.hash_val.clone(),
            child: vec![],
            is_transaction: true,
        }
    }
}
