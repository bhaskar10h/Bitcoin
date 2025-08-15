use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    thread::sleep,
    time::{Duration, Instant}
};

use lazy_static::lazy_static;
use prettytable::{Cell, Row, Table};
use rand::{Rng, rng};
use rsa::{pkcs1::EncodeRsaPublicKey, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

use crate::{
    bitcoinscript::ScriptSign,
    block::Block,
    blockchain::BlockChain,
    config::{ARITY, INCENTIVE, NO_OF_NODES, SIZE_OF_NONCE},
    hash_algo::generate_hash,
    merkle_node::MerkleNode,
    transaction::Transaction
};

#[derive(Clone)]
pub struct Node {
    id: usize,
    pubkey: Vec<RsaPublicKey>,
    pvtkey: Vec<RsaPrivateKey>,
    block_chain: BlockChain,
    transaction: Vec<Transaction>,
    blockqueue: Vec<Block>,
    target: Option<String>,
    incentive: u64,
    bitcoins: u64,
    start: Instant,
    utxo: HashMap<String, Vec<(Transaction, usize)>>,
}

impl Node {
    pub fn new(id: usize) -> Self {
        let mut pubkey = Vec::new();
        let mut pvtkey = Vec::new();
        let mut pubkey_map = PUBLIC_KEY_MAP.lock().unwrap();

        (0..5).for_each(|i| {
            let mut range = rng();
            let private_key =
                RsaPrivateKey::new(&mut range, 2048).expect("Failed to generate private key");
            let public_key = private_key.to_public_key();
            pubkey.push(public_key.clone());
            pvtkey.push(private_key.clone());
        });

        Self {
            id,
            pubkey,
            pvtkey,
            block_chain: BlockChain::new(),
            transaction: Vec::new(),
            blockqueue: Vec::new(),
            target: None,
            incentive: 0,
            bitcoins: 0,
            start: Instant::now(),
            utxo: HashMap::new(),
        }
    }

    pub fn get_wallet_addr(&self) -> String {
        let keyno = rng().random_range(0..5);
        let pubkey = &self.pubkey[keyno];
        let pubkey_bytes = pubkey
            .to_pkcs1_der()
            .expect("Failed to export public key")
            .clone();
        let mut hasher = Sha256::new();
        hasher.update(pubkey_bytes);
        generate_hash(&format!("{:x}", hasher.finalize()))
    }

    pub fn run(&mut self, all_nodes: Arc<Mutex<Vec<Arc<Mutex<Node>>>>>) {
        self.start = Instant::now();
        loop {
            let end = Instant::now();

            if end.duration_since(self.start) > Duration::from_secs(15) {
                if !self.transaction.is_empty() {
                    let blk = self.create_block();
                    self.target = Some(blk.hash_val.clone());
                    if self.proof_of_work(&all_nodes) {
                        let mut txn_flag = TXN_FLAG.lock().unwrap();
                        *txn_flag = false;

                        let mut flag = true;
                        all_nodes.lock().unwrap().iter().for_each(|node| {
                            if !node.lock().unwrap().get_consensus(&blk) {
                                flag = false;
                                true;
                            }

                            if flag {
                                println!("---------------------- Transactions Performed --------------------------");
                                let txns_performed = TXNS_PERFORMED.lock().unwrap();
                                println!("{}", txns_performed);
                                TXNS_PERFORMED.lock().unwrap().clear_rows();

                                println!("--------------------------------------------------------------------------");
                                all_nodes.lock().unwrap().iter().for_each(|node| node.lock().unwrap().process_blocks(blk));
                                println!("--------After Performing the Transaction final state of the Nodes---------");
                                self.print_utxo(&all_nodes);

                                println!("------------------------ Transactions Executed----------------------------");
                                self.print_txn(&all_nodes);

                                println!(" -------------------------------------------------------------------------- ");

                                *txn_flag = true;
                                TXN_NODES.lock().unwrap().clear();
                                self.incentive += INCENTIVE;
                                let randkeyno = rng().random_range(0..5);
                                let mut recv_pubkey_hash = Sha256::new();
                                let pubkey_bytes = self.pubkey[randkeyno].to_pkcs1_der().expect("Failed to export public key").as_ref();
                                recv_pubkey_hash.update(pubkey_bytes);
                                let recv_pubkey_hash_str = generate_hash(&format!("{:x}", recv_pubkey_hash.clone().finalize()));
                                let txn = Transaction::new(vec![], vec![], INCENTIVE, &mut recv_pubkey_hash, true);
                                all_nodes.lock().unwrap().iter().for_each(|node| node.lock().unwrap().process_transactions(&txn));
                                
                            } else {
                                self.transaction.clear();
                                *txn_flag = true;
                                TXN_NODES.lock().unwrap().clear();
                            }
                        });
                    } else {
                        self.start = Instant::now(); 
                    }
                }
            }

            let dotxn = rng().random::<f64>();
            let (txn_flag, mut txn_nodes) = (TXN_FLAG.lock().unwrap(), TXNS_PERFORMED.lock().unwrap());
            if dotxn <= 0.2 && *txn_flag && !txn_nodes.contains(&self.id) {
                let mut recv = rng().random_range(0..NO_OF_NODES);
                while recv == self.id {recv =rng().random_range(0..NO_OF_NODES);  }
                let recv_node = all_nodes.lock().unwrap()[recv].lock().unwrap();
                let recv_key_hash = recv_node.get_wallet_addr();
                let mut prev_txn = vec![];
                let mut script_sign = vec![];

                (0..5).for_each(|j| {
                    let pubkey = &self.pubkey[j];
                    let pvtkey = &self.pvtkey[j];
                    let pubkey_bytes = pubkey.to_pkcs1_der().expect("Failed to export public key").as_ref();
                    let mut hasher = Sha256::new();
                    hasher.update(pubkey_bytes);
                    let sender_pubkey_hash = generate_hash(&format!("{:x}", hasher.finalize()));


                    if let Some(txn_1) = self.utxo.get(&sender_pubkey_hash) {
                        txn_1.into_iter().for_each(|t| {
                            let mut hasher = Sha256::new();
                            hasher.update(pubkey_bytes);
                            hasher.update(t.0.hash_val.as_bytes());
                            let signature = pvtkey.sign(Pkcs1v15Sign::new(), &hasher.finalize()).expect("Failed to sign");
                            prev_txn.push((Box::new(t.0), t.1));
                            script_sign.push(ScriptSign {
                                sign: signature,
                                pubkey: pubkey.to_pkcs1_der().unwrap().as_ref().to_vec(), 
                            });        
                        });
                    }
                });

                let bitcoin_val = rng().random_range(10..=200);
                let mut recv_hasher = Sha256::new();
                recv_hasher.update(hex::decode(&recv_key_hash).unwrap());
                let new_txn = Transaction::new(prev_txn, script_sign, bitcoin_val, &mut recv_hasher, false);
                TXNS_PERFORMED.lock().unwrap().add_row(Row::new(vec![
                    Cell::new(&self.id.to_string()),
                    Cell::new(&PUBLIC_KEY_MAP.lock().unwrap()[&recv_key_hash]),
                    Cell::new(&bitcoin_val.to_string()),
                    Cell::new(&new_txn.valid_txn.to_string())
                ]));

                if new_txn.valid_txn {txn_nodes.push(self.id);}
                all_nodes.lock().unwrap().iter().for_each(|node| node.lock().unwrap().process_transactions(&new_txn)); 
            }

            drop(txn_flag);
            drop(txn_nodes);
            sleep(Duration::from_secs(1));
        }
    }

    pub fn get_consensus(&self, block: &Block ) -> bool {
        if self.block_chain.latest_block.as_ref().map_or(true, |b| b.hash_val != block.prev_block_hash) {
            return false;
        }

        block.txn_list.iter().for_each(|txn| {
           if !txn.valid_txn { ()  }                
           &txn.input.iter().for_each(|inp| {
               let sign = &inp.1.pubkey;
               let mut hasher = Sha256::new();
               hasher.update(sign);
               let sign_hash = generate_hash(&format!("{:x}", hasher.finalize()));
               if let Some(utxo) = self.utxo.get(&sign_hash) {
                   if !utxo.iter().any(|(txn, idx)| txn.hash_val == inp.0.0.hash_val && *idx == inp.0.1) { () } 
               } else { return () }
           }); 
        });
        true 
    }


    pub fn generate_nonce(&self) -> u64 {
        rng().random_range(0..2u64.pow(SIZE_OF_NONCE as u32))
    }

    pub fn process_transactions(&mut self, txn: &Transaction) {
        if txn.valid_txn {
            self.transaction.push(txn.clone());
        }
    }

    pub fn process_block(&mut self, block: &Block) {
        if self.block_chain.latest_block.is_none() {
            self.block_chain.root_block = Some(block.clone());
        }
        self.block_chain.latest_block = Some(block.clone());
        let mut temp_utxo: HashMap<String, Vec<(Transaction, usize)>> = HashMap::new();

        block.txn_list.iter().for_each(|txn| {
            txn.input.iter().for_each(|x| {
                let index = x.0.1;
                let script_pubkey = x.0.0.output[index].1.pubkey_hash;
                self.utxo.remove(&script_pubkey);
            });
            let mut index = 0;
            txn.output.iter().for_each(|x| {
                let script_pubkey = x.1.pubkey_hash_key();
                temp_utxo.entry(script_pubkey.clone())
                         .or_insert_with(|| Vec::new())
                         .push((txn.clone(), index));
                index += 1; 
            });
            self.transaction.retain(|t| t.hash_val != txn.hash_val);
        });

        temp_utxo.into_iter().for_each(|(key, val)| {
            self.utxo.entry(key).or_insert_with(|| Vec::new()).extend(val);
        });
        self.start = Instant::now();
    }

    
    pub fn create_genesis_block(&mut self, all_nodes: Arc<Mutex<Vec<Arc<Mutex<Node>>>>>) {
        let bitcoin_value = 1000;
        for _ in 0..NO_OF_NODES {
            let random_no = rng().random_range(0..NO_OF_NODES);
            let rand_key_no = rng().random_range(0..5);
            let node = all_nodes.lock().unwrap()[random_no].lock().unwrap();
            let pub_key_bytes = node.pubkey[rand_key_no].to_pkcs1_der().expect("Failed to export public key").as_ref();
            let mut recvr_pubkey_hash = Sha256::new();
            recvr_pubkey_hash.update(pub_key_bytes);
            let t1 = Transaction::new(vec![], vec![], bitcoin_value, &mut recvr_pubkey_hash, true);
            self.transaction.push(t1);
        }
        let txn = self.transaction.clone();
        let root_merkle_tree = self.generate_merkle_tree(&txn);
        let blk = Block::new(self.block_chain.latest_block.clone(), root_merkle_tree, self.generate_nonce(), txn);
        for node in all_nodes.lock().unwrap().iter() {
            node.lock().unwrap().process_blocks(blk);
        }
        self.transaction.clear();
    }

    pub fn create_block(&self) -> Block {
        let txn = self.transaction.clone();
        let root_merkle_tree = self.generate_merkle_tree(&txn);
        Block::new(self.block_chain.latest_block.clone(), root_merkle_tree, self.generate_nonce(), txn)
    }

    pub fn generate_merkle_tree(&self, txns: &[Transaction]) -> MerkleNode {
        let mut childs: Vec<(MerkleNode, usize)> = txns.iter()
            .map(|t| (MerkleNode::from_transaction(t), 0))
            .collect();

        while childs.len() > 1 {
            let level = childs[0].1;
            let mut merkle_tree_child = vec![];
            for _ in 0..ARITY {
                if !childs.is_empty() && childs[0].1 == level {
                    merkle_tree_child.push(childs[0].0.clone());
                    childs.remove(0);
                }
            }
            childs.push((MerkleNode::new(merkle_tree_child, false), level + 1));
        }
        childs[0].0.clone()
    }

    
    pub fn proof_of_work(&self, all_nodes: &Arc<Mutex<Vec<Arc<Mutex<Node>>>>>) -> bool {
        for node in all_nodes.lock().unwrap().iter() {
            let node = node.lock().unwrap();
            if let Some(target) = &node.target {
                if self.target.as_ref().map_or(false, |t| t > target) {
                    return false;
                }
                if self.id != node.id && self.target == node.target && self.id > node.id {
                    return false;
                }
            }
        }
        true
    }

    
    pub fn process_blocks(&mut self, block: Block) {
            if self.block_chain.root_block.is_none() {
                self.block_chain.root_block = Some(block.clone());
            }

            self.block_chain.latest_block = Some(block.clone());
            let mut temp_unspent_outputs: std::collections::HashMap<String, Vec<(Transaction, usize)>> = std::collections::HashMap::new();

            for txns in &block.txn_list {
                for x in &txns.input {
                    let index = x.0.1;
                    let script_pub_key = x.0.0.output[index].1.pubkey_hash_key();
                    self.utxo.remove(&script_pub_key);
                }
                let mut index = 0;
                for x in &txns.output {
                    let script_pub_key = x.1.pubkey_hash_key();
                    temp_unspent_outputs.entry(script_pub_key.clone())
                        .or_insert_with(Vec::new)
                        .push((txns.clone(), index));
                    index += 1;
                }

                self.transaction.retain(|t| t.hash_val != txns.hash_val);
            }

            for (key, val) in temp_unspent_outputs {
                self.utxo.entry(key)
                    .or_insert_with(Vec::new)
                    .extend(val);
            }
            self.start = Instant::now();
        }

    pub fn print_txn(&self, txn_list: &Arc<Mutex<Vec<Arc<Mutex<Transaction>>>>>) {
        let mut txns_executed = Table::new();
        txns_executed.add_row(Row::new(vec![
            Cell::new("ID"),
            Cell::new("IN/OUT"),
            Cell::new("Wallet ID"),
            Cell::new("Amount"),
        ]));

        for (i, txn) in txn_list.lock().unwrap().iter().enumerate() {
            for inp in &txn.lock().unwrap().input {
                let wallet_amt = inp.0.0.output[inp.0.1].0;
                let mut hasher = Sha256::new();
                hasher.update(&inp.1.pubkey);
                let pub_key_hash = generate_hash(&format!("{:x}", hasher.finalize()));
                txns_executed.add_row(Row::new(vec![
                    Cell::new(&i.to_string()),
                    Cell::new("IN"),
                    Cell::new(&PUBLIC_KEY_MAP.lock().unwrap()[&pub_key_hash]),
                    Cell::new(&wallet_amt.to_string()),
                ]));
            }
            for otp in &txn.lock().unwrap().output {
                let wallet_amt = otp.0;
                let pub_key_hash = otp.1.pubkey_hash_key();
                txns_executed.add_row(Row::new(vec![
                    Cell::new(&i.to_string()),
                    Cell::new("OUT"),
                    Cell::new(&PUBLIC_KEY_MAP.lock().unwrap()[&pub_key_hash]),
                    Cell::new(&wallet_amt.to_string()),
                ]));
            }
        }
        println!("{}", txns_executed);
    }

    pub fn print_utxo(&self, all_nodes: &Arc<Mutex<Vec<Arc<Mutex<Node>>>>>) {
        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new("Node ID"),
            Cell::new("Wallet 0"),
            Cell::new("Wallet 1"),
            Cell::new("Wallet 2"),
            Cell::new("Wallet 3"),
            Cell::new("Wallet 4"),
        ]));

        for node in all_nodes.lock().unwrap().iter() {
            let node = node.lock().unwrap();
            let mut row = vec![Cell::new(&node.id.to_string())];
            for i in 0..5 {
                let pub_key_bytes = node.pubkey[i].to_pkcs1_der().unwrap();
                let mut hasher = Sha256::new();
                hasher.update(pub_key_bytes);
                let pub_key_hash = generate_hash(&format!("{:x}", hasher.finalize()));
                let mut amt = 0;
                if let Some(val) = node.utxo.get(&pub_key_hash) {
                    for (txn, ind) in val {
                        amt += txn.output[*ind].0;
                    }
                }
                row.push(Cell::new(&amt.to_string()));
            }
            table.add_row(Row::new(row));
        }
        println!("{}", table);
        println!("--------------------------------------------------------------------------------");
    }
}


lazy_static! {
    static ref ALL_NODES: Arc<Mutex<Vec<Arc<Mutex<Node>>>>> = Arc::new(Mutex::new(Vec::new()));
    static ref TXN_FLAG: Arc<Mutex<bool>> = Arc::new(Mutex::new(true));
    static ref TXN_NODES: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
    static ref TXNS_PERFORMED: Arc<Mutex<Table>> = Arc::new(Mutex::new({
        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new("Sender"),
            Cell::new("Receiver"),
            Cell::new("Amount"),
            Cell::new("Valid"),
        ]));
        table
    }));
    static ref PUBLIC_KEY_MAP: Arc<Mutex<std::collections::HashMap<String, String>>> = Arc::new(Mutex::new(std::collections::HashMap::new()));
}    

