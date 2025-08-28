use std::{
    sync::{Arc, Mutex},
    thread,
};

use crate::{
    config::NO_OF_NODES,
    node::{ALL_NODES, Node},
};

mod bitcoinscript;
mod block;
mod blockchain;
mod config;
mod hash_algo;
mod merkle_node;
mod node;
mod transaction;

fn main() {
    println!("Starting Bitcoin Simulation...");

    let nodes = (0..NO_OF_NODES)
        .map(|i| Arc::new(Mutex::new(Node::new(i))))
        .collect::<Vec<_>>();
    *ALL_NODES.lock().unwrap() = nodes.clone();

    // Creating Genesis Block
    {
        let all_nodes_locked = ALL_NODES.clone();
        nodes[0]
            .lock()
            .unwrap()
            .create_genesis_block(all_nodes_locked);
    }

    println!("Genesis Block created and distributed!...");
    println!("--------------------------------------------------------------");
    println!("Initializing State of Wallets (Bitcoins per wallets)...");

    nodes[0].lock().unwrap().print_utxo(&ALL_NODES);

    let mut handles = vec![];
    for node_arc in nodes {
        let all_nodes_clone = ALL_NODES.clone();
        let handler = thread::spawn(move || {
            node_arc.lock().unwrap().run(all_nodes_clone);
        });
        handles.push(handler);
    }

    println!("All Nodes are running concurrently!...");

    for handle in handles {
        handle.join().unwrap();
    }
}
