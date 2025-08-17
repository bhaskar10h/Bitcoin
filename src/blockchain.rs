use std::sync::{Arc, Mutex};

use crate::block::Block;

type BlockPtr = Option<Arc<Mutex<Block>>>;

#[derive(Clone)]
pub struct BlockChain {
    pub latest_block: BlockPtr,
    pub root_block: BlockPtr,
}

impl BlockChain {
    pub fn new() -> Self {
        Self {
            latest_block: None,
            root_block: None,
        }
    }
}
