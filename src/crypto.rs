use aes::{Aes128, Aes256};
use sha3::digest::FixedOutputReset;
use sha3::{Digest, Keccak256};

pub type Aes128CTR = ctr::Ctr128BE<Aes128>;
pub type Aes256CTR = ctr::Ctr128BE<Aes256>;

// a quick helper function to keccak256 hash two inputs (most of the cases in eth secrets computation
pub fn keccak256_hash(input1: &[u8], input2: &[u8]) -> Vec<u8> {
    let mut hasher = Keccak256::default();
    hasher.update(input1);
    hasher.update(input2);
    hasher.finalize_fixed_reset().to_vec()
}

pub fn init_keccak256_hasher(mac: &[u8], nonce: &[u8], data: &[u8]) -> Keccak256 {
    let mut hasher = Keccak256::default();
    // hash ( mac ^ nonce )
    hasher.update(
        &mac.iter()
            .zip(nonce.iter())
            .map(|v| *v.0 ^ *v.1)
            .collect::<Vec<u8>>(),
    );
    hasher.update(data);
    hasher
}

// directly ported from eth until it's figured out how it actually works
pub struct HashMac {
    cipher: Aes256,
    hasher: Keccak256,
}

impl HashMac {
    pub fn new(cipher: Aes256, hasher: Keccak256) -> Self {
        Self { cipher, hasher }
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::keccak256_hash;

    #[test]
    pub fn keccak256_helper_sanity_test() -> anyhow::Result<()> {
        let res = keccak256_hash(b"hello", b"world");

        // expected result taken from https://emn178.github.io/online-tools/keccak_256.html
        Ok(assert_eq!(
            "fa26db7ca85ead399216e7c6316bc50ed24393c3122b582735e7f3b0f91b93f0".to_string(),
            hex::encode(&res)
        ))
    }
}
