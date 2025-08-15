use rsa::{RsaPublicKey, pkcs1::DecodeRsaPublicKey, traits::PaddingScheme};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy)]
pub struct ScriptPubkey {
    pub pubkey_hash: [u8; 32],
    pub recvkey_hash: [u8; 32],
}

impl ScriptPubkey {
    pub fn new(pubkey_hash: Sha256, _pubkey_hash_hex: String) -> Self {
        let mut recvkey_hash = [0u8; 32];
        recvkey_hash.copy_from_slice(&pubkey_hash.finalize()[..32]);
        Self {
            pubkey_hash: recvkey_hash,
            recvkey_hash,
        }
    }

    pub fn pubkey_hash_key(&self) -> String {
        hex::encode(self.pubkey_hash)
    }
}

#[derive(Clone)]
pub struct ScriptSign {
    pub sign: Vec<u8>,
    pub pubkey: Vec<u8>,
}

pub fn execute_script(
    script_sign: &ScriptSign,
    script_pubkey: &ScriptPubkey,
    hash_val: &str,
) -> bool {
    let signature = &script_sign.sign;
    let pubkey = &script_sign.pubkey;
    let pubkey_hash = &script_pubkey.pubkey_hash;

    let mut hasher = Sha256::new();
    hasher.update(pubkey);
    let hash_out = hasher.finalize();

    if &hash_out[..] != pubkey_hash {
        return false;
    }

    let pubkey_str = match std::str::from_utf8(pubkey) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let rsa_pub = match RsaPublicKey::from_pkcs1_pem(pubkey_str) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let mut msg_hasher = Sha256::new();
    msg_hasher.update(hash_val.as_bytes());
    let hash_msg = msg_hasher.finalize();

    let padding = PaddingScheme::new_pkcs1v15_sign();
    match rsa_pub.verify(padding, &hash_msg, signature) {
        Ok(_) => true,
        Err(_) => false,
    }
}
