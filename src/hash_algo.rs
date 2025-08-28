use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

use crate::config::HASH_SIZE;

pub fn generate_hash(message: &str) -> String {
    match HASH_SIZE {
        224 => {
            let mut hasher = Sha224::new();
            hasher.update(message.as_bytes());
            format!("{:x}", hasher.finalize())
        }

        256 => {
            let mut hasher = Sha256::new();
            hasher.update(message.as_bytes());
            format!("{:x}", hasher.finalize())
        }

        384 => {
            let mut hasher = Sha384::new();
            hasher.update(message.as_bytes());
            format!("{:x}", hasher.finalize())
        }

        _ => {
            let mut hasher = Sha512::new();
            hasher.update(message.as_bytes());
            format!("{:x}", hasher.finalize())
        }
    }
}
