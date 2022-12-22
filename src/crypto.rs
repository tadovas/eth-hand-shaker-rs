use aes::cipher::BlockEncrypt;
use aes::{Aes128, Aes256};
use anyhow::anyhow;
use cipher::block_padding::NoPadding;
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

// directly ported from eth until all the magic is figured out
pub struct HashMac {
    cipher: Aes256,
    hasher: Keccak256,
    // initialized to zeros on creation
    aes_buffer: [u8; 16], // we assume AES256 but 256 (32 bytes) is key size, block size is always 16
    hash_buffer: [u8; 32],
    seed_buffer: [u8; 32],
}

impl HashMac {
    pub fn new(cipher: Aes256, hasher: Keccak256) -> Self {
        Self {
            cipher,
            hasher,
            aes_buffer: [0; 16],
            hash_buffer: [0; 32],
            seed_buffer: [0; 32],
        }
    }

    // input is 16 bytes header data (already encrypted), result is always 16 bytes mac
    pub fn compute_header_mac(&mut self, header_data: &[u8]) -> anyhow::Result<Vec<u8>> {
        // write current hash into hash_buffer
        Digest::finalize_into_reset(&mut self.hasher, &mut self.hash_buffer.into());

        let hash_buffer = self.hash_buffer[..].to_vec();
        self.compute(&hash_buffer, header_data)
    }

    // input is frame data aligned to 16 bytes blocks, result is always 16 bytes mac
    pub fn compute_frame_mac(&mut self, frame_data: &[u8]) -> Vec<u8> {
        Vec::new()
    }

    // does all eth magic, returns lower 16 bytes of hash as mac
    fn compute(&mut self, sum: &[u8], seed: &[u8]) -> anyhow::Result<Vec<u8>> {
        // at this moment sum.len() == seed.len()
        println!("Sum length: {}", sum.len());
        self.cipher
            .encrypt_padded_b2b::<'_, NoPadding>(&sum[..16], &mut self.aes_buffer)
            .map_err(|e| anyhow!("aes encrypt: {}", e))?;
        // xor aes_buffer with seed
        for (res_byte, seed_byte) in self.aes_buffer.iter_mut().zip(seed.iter()) {
            *res_byte = *res_byte ^ *seed_byte
        }
        self.hasher.update(self.aes_buffer);
        Digest::finalize_into_reset(&mut self.hasher, &mut self.hash_buffer.into());
        Ok(self.hash_buffer[..16].to_vec())
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
