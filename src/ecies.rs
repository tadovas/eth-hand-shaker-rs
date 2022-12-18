use aes::cipher::consts::{U16, U32};
use aes::cipher::generic_array::GenericArray;
use aes::cipher::KeyIvInit;
use aes::cipher::{BlockSizeUser, KeyInit, StreamCipher};
use aes::Aes128;
use anyhow::anyhow;
use secp256k1::ecdh::SharedSecret;
use secp256k1::hashes::sha256;
use secp256k1::rand::rngs::OsRng;
use secp256k1::rand::RngCore;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use std::io::Write;
use tokio::io::AsyncWriteExt;

/*
ECIES_AES128_SHA256 = &ECIESParams{
        Hash:      sha256.New,
        hashAlgo:  crypto.SHA256,
        Cipher:    aes.NewCipher,
        BlockSize: aes.BlockSize,
        KeyLen:    16,
    }

 */
type Aes128CTR32BE = ctr::Ctr32BE<Aes128>;

pub async fn encrypt(
    msg: &[u8],
    peer_public_key: &PublicKey,
    s1: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let secp = Secp256k1::new();
    let mut os_rng = OsRng;
    let private_ephemeral = SecretKey::new(&mut os_rng);

    let shared_secret = SharedSecret::new(peer_public_key, &private_ephemeral);

    let (enc_key, auth_key) = derive_keys(shared_secret.as_ref(), s1)?;

    let mut iv = [0u8; 16];
    os_rng.fill_bytes(&mut iv);
    let mut cipher = Aes128CTR32BE::new(&enc_key, &iv.into());
    let mut encrypted = msg.to_vec();
    let padding_size = encrypted.len() % 16;
    if padding_size > 0 {
        let mut padding = Vec::with_capacity(padding_size);
        os_rng.fill_bytes(&mut padding[..]);
        encrypted.extend_from_slice(&padding[..])
    }
    cipher.apply_keystream(&mut encrypted[..]);

    let mut result = Vec::with_capacity(65 + 16 + encrypted.len() + 32); // according to eth: pub key, iv, encrypted data, digest
    result.extend_from_slice(&private_ephemeral.public_key(&secp).serialize_uncompressed()[..]);
    result.extend_from_slice(&iv);
    result.extend_from_slice(&encrypted);
    let digest = [0u8; 32];
    result.extend_from_slice(&digest);
    Ok(result)
}

fn derive_keys(
    msg: &[u8],
    s1: &[u8],
) -> anyhow::Result<((GenericArray<u8, U16>, GenericArray<u8, U32>))> {
    let mut derived_key = [0u8; 16 * 2]; // taken from eth - actually we derive TWO keys at the same time each 16 bytes
    concat_kdf::derive_key_into::<Sha256>(msg, s1, &mut derived_key)
        .map_err(|err| anyhow!("concat-KDF: {}", err))?;
    let second_part = Sha256::digest(&derived_key[16..]);

    let enc_key = GenericArray::clone_from_slice(&derived_key[..16]);
    let auth_key = GenericArray::clone_from_slice(second_part.as_ref());

    Ok((enc_key, auth_key))
}
