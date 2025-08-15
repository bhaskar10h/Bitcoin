use crate::bitcoinscript::{ScriptPubkey, ScriptSign, execute_script};
use crate::hash_algo::generate_hash;
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct Transaction {
    pub hash_val: String,
    pub input: Vec<((Box<Transaction>, usize), ScriptSign)>,
    pub output: Vec<(u64, ScriptPubkey)>,
    pub valid_txn: bool,
}

impl Transaction {
    pub fn new(
        prev_txn: Vec<(Box<Self>, usize)>,
        script_sign: Vec<ScriptSign>,
        mut amnt: u64,
        recv_pubkey_hash: &mut Sha256,
        genesis_block_txn: bool,
    ) -> Self {
        let mut all_hash = String::new();
        prev_txn.iter().for_each(|(txn, idx)| {
            all_hash.push_str(&txn.hash_val);
            all_hash.push_str(&idx.to_string());
        });

        let input: Vec<((Box<Self>, usize), ScriptSign)> =
            prev_txn.into_iter().zip(script_sign).collect();
        let mut output = Vec::new();
        let mut valid_txn = true;

        if genesis_block_txn {
            let script_pubkey = ScriptPubkey::new(
                recv_pubkey_hash.clone(),
                hex::encode(recv_pubkey_hash.clone().finalize()),
            );
            output.push((amnt, script_pubkey));

            (output).iter().for_each(|(val, spk)| {
                all_hash.push_str(&val.to_string());
                all_hash.push_str(&spk.pubkey_hash_key());
            });

            let hash_val = generate_hash(&all_hash);
            recv_pubkey_hash.update(hash_val.as_bytes());

            return Self {
                hash_val,
                output,
                input,
                valid_txn,
            };
        }

        let valid_coins = Self::is_valid_transaction(&input, amnt);
        if valid_coins == -1 {
            let hash_val = generate_hash(&all_hash);
            return Self {
                hash_val,
                input,
                output,
                valid_txn: false,
            };
        };

        let script_pubkey = ScriptPubkey::new(
            recv_pubkey_hash.clone(),
            hex::encode(recv_pubkey_hash.clone().finalize()),
        );
        output.push((amnt, script_pubkey));

        if valid_coins > amnt as i64 {
            input.iter().for_each(|((txn, idx), sign)| {
                let mut wallet_amnt = txn.output[*idx].0;
                let mut paid_amnt = 0;
                let mut balance_wallet_amnt = wallet_amnt;

                if amnt > 0 {
                    paid_amnt = wallet_amnt.min(amnt);
                    balance_wallet_amnt -= paid_amnt;
                    amnt -= paid_amnt;
                }

                if balance_wallet_amnt > 0 {
                    let sender_pubkey_hash = Sha256::digest(&sign.pubkey);
                    let spk = ScriptPubkey::new(
                        Sha256::new_with_prefix(&sender_pubkey_hash),
                        hex::encode(sender_pubkey_hash),
                    );
                    output.push((balance_wallet_amnt, spk));
                }
            });
        }

        output.iter().for_each(|(val, spk)| {
            all_hash.push_str(&val.to_string());
            all_hash.push_str(&spk.pubkey_hash_key());
        });
        let hash_val = generate_hash(&all_hash);

        output.iter_mut().for_each(|(_, spk)| {
            spk.update_hash(&hash_val);
        });

        Self {
            hash_val,
            input,
            output,
            valid_txn,
        }
    }

    fn is_valid_transaction(inputs: &Vec<((Box<Self>, usize), ScriptSign)>, amount: u64) -> i64 {
        let mut valid_bitcoins: i64 = 0;
        inputs.iter().for_each(|((txn, idx), script_signature)| {
            let txnhash = &txn.hash_val;
            let script_pubkey = txn.output[*idx].1;

            if !execute_script(script_signature, &script_pubkey, txnhash) {
                ()
            }

            valid_bitcoins += txn.output[*idx].0 as i64;

            if valid_bitcoins > amount as i64 {
                ()
            }
        });
        valid_bitcoins
    }

    pub fn get_size(&self) -> usize {
        let mut total_size = 0;
        total_size += self.hash_val.len();
        total_size += std::mem::size_of_val(&self.input);
        total_size += std::mem::size_of_val(&self.output);
        total_size
    }
}
