use crate::block::Block;

#[derive(Clone)]
pub struct BlockChain {
    pub latest_block: Option<Block>,
    pub root_block: Option<Block>,
}

impl BlockChain {
    pub fn new() -> Self {
        Self {
            latest_block: None,
            root_block: None,
        }
    }
}
