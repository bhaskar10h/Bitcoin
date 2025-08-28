use crate::bitcoinscript::{ScriptPubkey, ScriptSign, execute_script};
use crate::hash_algo::generate_hash;
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct Transaction {
    pub hash_val: String,
    pub input: Vec<((Box<Transaction>, usize), ScriptSign)>,
    pub output: Vec<(u64, ScriptPubkey)>,
    pub valid_txn: bool,
    pub is_coinbase: bool,
}

impl Transaction {
    pub fn new(
        prev_txn: Vec<(Box<Self>, usize)>,
        script_sign: Vec<ScriptSign>,
        amnt: u64,
        recv_pubkey_hash: &mut Sha256,
        is_coinbase: bool,
    ) -> Self {
        let mut all_hash = String::new();
        prev_txn.iter().for_each(|(txn, idx)| {
            all_hash.push_str(&txn.hash_val);
            all_hash.push_str(&idx.to_string());
        });

        let input: Vec<((Box<Self>, usize), ScriptSign)> =
            prev_txn.into_iter().zip(script_sign).collect();
        let mut output = Vec::new();

        if is_coinbase {
            let script_pubkey = ScriptPubkey::new(recv_pubkey_hash.clone());
            output.push((amnt, script_pubkey));

            output.iter().for_each(|(val, spk)| {
                all_hash.push_str(&val.to_string());
                all_hash.push_str(&spk.pubkey_hash_key());
            });
            let hash_val = generate_hash(&all_hash);

            return Self {
                hash_val,
                output,
                input,
                valid_txn: true,
                is_coinbase,
            };
        }

        let total_input_value = Self::get_total_input_value(&input);
        if total_input_value < 0 || (total_input_value as u64) < amnt {
            return Self {
                hash_val: String::new(),
                input,
                output,
                valid_txn: false,
                is_coinbase,
            };
        }

        let script_pubkey = ScriptPubkey::new(recv_pubkey_hash.clone());
        output.push((amnt, script_pubkey));

        let change = total_input_value as u64 - amnt;
        if change > 0 {
            if let Some(((_, _), sign)) = input.first() {
                let sender_pubkey_hash_bytes: [u8; 32] = Sha256::digest(&sign.pubkey).into();
                let spk = ScriptPubkey::new(Sha256::new_with_prefix(sender_pubkey_hash_bytes));
                output.push((change, spk));
            }
        }

        output.iter().for_each(|(val, spk)| {
            all_hash.push_str(&val.to_string());
            all_hash.push_str(&spk.pubkey_hash_key());
        });
        let hash_val = generate_hash(&all_hash);

        Self {
            hash_val,
            input,
            output,
            valid_txn: true,
            is_coinbase,
        }
    }

    fn get_total_input_value(inputs: &[((Box<Self>, usize), ScriptSign)]) -> i64 {
        let mut total_value: i64 = 0;
        for ((txn, idx), script_signature) in inputs {
            let txnhash = &txn.hash_val;
            let script_pubkey = &txn.output[*idx].1;
            if !execute_script(script_signature, script_pubkey, txnhash) {
                // if fails, entire trxn becomes invalid
                return -1;
            }
            total_value += txn.output[*idx].0 as i64;
        }
        total_value
    }

    pub fn get_size(&self) -> usize {
        let mut total_size = 0;
        total_size += self.hash_val.len();
        for ((_, _), scriptsign) in &self.input {
            total_size += 8;
            total_size += scriptsign.sign.len();
            total_size += scriptsign.pubkey.len();
        }
        for (amount, script_pubkey) in &self.output {
            total_size += std::mem::size_of_val(amount);
            total_size += script_pubkey.pubkey_hash.len();
        }
        total_size
    }
}
