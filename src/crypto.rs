use aes::cipher::BlockEncrypt;
use aes::{Aes128, Aes256};
use anyhow::anyhow;
use cipher::block_padding::NoPadding;
use sha3::digest::{FixedOutputReset, Output};
use sha3::{Digest, Keccak256};
use std::cell::RefCell;

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
    cipher: RefCell<Aes256>,
    hasher: RefCell<Keccak256>,
    // initialized to zeros on creation
    aes_buffer: RefCell<[u8; 16]>, // we assume AES256 but 256 (32 bytes) is key size, block size is always 16
    hash_buffer: RefCell<[u8; 32]>,
    seed_buffer: RefCell<[u8; 32]>,
}

impl HashMac {
    pub fn new(cipher: Aes256, hasher: Keccak256) -> Self {
        Self {
            cipher: RefCell::new(cipher),
            hasher: RefCell::new(hasher),
            aes_buffer: RefCell::new([0; 16]),
            hash_buffer: RefCell::new([0; 32]),
            seed_buffer: RefCell::new([0; 32]),
        }
    }

    // input is 16 bytes header data (already encrypted), result is always 16 bytes mac
    pub fn compute_header_mac(&self, header_data: &[u8]) -> anyhow::Result<Vec<u8>> {
        // write current hash into hash_buffer
        let data = {
            let mut mut_output_slice = self.hash_buffer.borrow_mut();
            let output = Output::<Keccak256>::from_mut_slice(mut_output_slice.as_mut_slice());
            Digest::finalize_into(self.hasher.borrow().clone(), output);
            mut_output_slice.to_vec()
        };

        self.compute(&data, header_data)
    }

    // input is frame data aligned to 16 bytes blocks, result is always 16 bytes mac
    pub fn compute_frame_mac(&mut self, frame_data: &[u8]) -> Vec<u8> {
        Vec::new()
    }

    // does all eth magic, returns lower 16 bytes of hash as mac
    fn compute(&self, sum: &[u8], seed: &[u8]) -> anyhow::Result<Vec<u8>> {
        // at this moment sum.len() == seed.len()
        self.cipher
            .borrow()
            .encrypt_padded_b2b::<NoPadding>(
                &sum[..16],
                self.aes_buffer.borrow_mut().as_mut_slice(),
            )
            .map_err(|e| anyhow!("aes encrypt: {}", e))?;
        // xor aes_buffer with seed
        for (res_byte, seed_byte) in self.aes_buffer.borrow_mut().iter_mut().zip(seed.iter()) {
            *res_byte ^= *seed_byte
        }
        self.hasher
            .borrow_mut()
            .update(self.aes_buffer.borrow().as_slice());

        let mut mut_output_slice = self.hash_buffer.borrow_mut();
        let output = Output::<Keccak256>::from_mut_slice(mut_output_slice.as_mut_slice());
        Digest::finalize_into(self.hasher.borrow().clone(), output);
        Ok(output.as_slice()[..16].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::{init_keccak256_hasher, keccak256_hash, HashMac};
    use aes::Aes256;
    use cipher::generic_array::GenericArray;
    use cipher::KeyInit;
    use sha3::digest::{FixedOutput, FixedOutputReset, Output};
    use sha3::{Digest, Keccak256};

    #[test]
    pub fn keccak256_helper_sanity_test() -> anyhow::Result<()> {
        let res = keccak256_hash(b"hello", b"world");

        // expected result taken from https://emn178.github.io/online-tools/keccak_256.html
        Ok(assert_eq!(
            "fa26db7ca85ead399216e7c6316bc50ed24393c3122b582735e7f3b0f91b93f0".to_string(),
            hex::encode(&res)
        ))
    }

    #[test]
    pub fn mac_hasher_header_computation_sanity_test() -> anyhow::Result<()> {
        // inputs and outputs taken from eth rplx tests (forked and crafted, not in master)
        let init_key =
            hex::decode("80e8632c05fed6fc2a13b0f8d31a3cf645366239170ea067065aba8e28bac487")?;
        let mut hasher = Keccak256::default();
        hasher.update(b"init data");

        let init_key = GenericArray::from_slice(&init_key);

        let cipher = Aes256::new(init_key);

        let mut hash_mac = HashMac::new(cipher, hasher);
        let header = hex::decode("00112233445566778899AABBCCDDEEFF")?;
        let computed = hash_mac.compute_header_mac(&header)?;
        Ok(assert_eq!(
            "ec4e4afd93e4069e440dc4ce59e2abed".to_string(),
            hex::encode(&computed)
        ))
    }

    #[test]
    pub fn keccak256_hasher_sanity_check() -> anyhow::Result<()> {
        let mut hasher = Keccak256::default();
        hasher.update(b"abc");
        let mut output: [u8; 32] = [0u8; 32];
        let output_obj = Output::<Keccak256>::from_mut_slice(&mut output);
        Digest::finalize_into(hasher.clone(), output_obj);

        println!("Intermediate: {}", hex::encode(output_obj.to_vec()));

        hasher.update(b"def");
        Digest::finalize_into(hasher.clone(), output_obj);
        println!("Final: {}", hex::encode(output_obj.to_vec()));

        hasher.reset();
        hasher.update(b"123");
        let output = hasher.finalize_fixed_reset();
        println!("After reset: {}", hex::encode(output));
        Ok(())
    }

    #[test]
    pub fn keccak256_init_test() {
        // input and output - from eth tests
        let hasher = init_keccak256_hasher(b"MAC", b"nonce", b"data");
        let hash = hasher.finalize_fixed();
        assert_eq!(
            "9116b0aa66f6d1d0d6aa3da440c9721b45df1e0fa1266024b80e26e54e60dea8".to_string(),
            hex::encode(hash)
        )
    }
}
