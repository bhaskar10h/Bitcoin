use rsa::{RsaPublicKey, pkcs1::DecodeRsaPublicKey, traits::PaddingScheme};
use sha2::{Digest, Sha256};

pub struct ScriptPubKey {
    pub pubkey_hash: [u8; 32],
    pub reckey_hash: [u8; 32],
}

pub struct ScriptSign {
    pub sign: Vec<u8>,
    pub pubkey: Vec<u8>,
}

pub fn execute_script(
    script_sign: &ScriptSign,
    script_pubkey: &ScriptPubKey,
    hash_val: &str,
) -> bool {
    let signature = &script_sign.sign;
    let sign_pubkey = &script_sign.pubkey;
    let pubkey_hash = script_pubkey.pubkey_hash;

    // generating public key hash
    let mut hasher = Sha256::new();
    hasher.update(sign_pubkey);
    let hash_out = hasher.finalize();

    if &hash_out[..] != pubkey_hash {
        return false;
    }

    //generating public key to rsa-public key
    let pubkey_str = match std::str::from_utf8(&sign_pubkey) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let rsa_pub = match RsaPublicKey::from_pkcs1_pem(pubkey_str) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // hashing the message that is signed
    let mut msg_hasher = Sha256::new();
    msg_hasher.update(hash_val.as_bytes());
    let hashed_msg = msg_hasher.finalize();

    // verifying the key
    let padding = PaddingScheme::new_pkcs1v15_sign();
    match rsa_pub.verify(padding, &hashed_msg, &signature) {
        Ok(_) => true,
        Err(_) => false,
    }
}
