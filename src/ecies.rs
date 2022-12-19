use aes::cipher::consts::{U16, U32};
use aes::cipher::generic_array::GenericArray;
use aes::cipher::KeyIvInit;
use aes::cipher::StreamCipher;
use aes::Aes128;
use anyhow::anyhow;
use secp256k1::ecdh::{shared_secret_point, SharedSecret};
use secp256k1::hashes::hex::ToHex;
use secp256k1::hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
use secp256k1::rand::rngs::OsRng;
use secp256k1::rand::RngCore;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

/*
ECIES_AES128_SHA256 = &ECIESParams{
        Hash:      sha256.New,
        hashAlgo:  crypto.SHA256,
        Cipher:    aes.NewCipher,
        BlockSize: aes.BlockSize,
        KeyLen:    16,
    }

 */

// according to eth go impl:
// encrypted message consists of:
// public key (size 65 - uncompressed)
// initial vector (16)
// <encrypted message itself>
// hmac signature (32)
pub const ECIES_OVERHEAD: usize = 65 + 16 + 32;

type Aes128CTR = ctr::Ctr128BE<Aes128>;

pub fn encrypt(
    msg: &[u8],
    peer_public_key: &PublicKey,
    s1: &[u8],
    s2: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let secp = Secp256k1::new();
    let mut os_rng = OsRng;
    let private_ephemeral = SecretKey::new(&mut os_rng);

    let shared_secret = shared_secret(peer_public_key, &private_ephemeral);

    let (enc_key, auth_key) = derive_keys(shared_secret.as_ref(), s1)?;

    let mut iv = [0u8; 16];
    os_rng.fill_bytes(&mut iv);
    let mut cipher = Aes128CTR::new(&enc_key, &iv.into());

    let mut result = Vec::with_capacity(msg.len() + ECIES_OVERHEAD); // according to eth: pub key, iv, encrypted data, digest
    result.extend_from_slice(&private_ephemeral.public_key(&secp).serialize_uncompressed()[..]);
    result.extend_from_slice(&iv);
    // extend with original message first
    result.extend_from_slice(msg);
    // and then apply in-place encryption
    let encryption_part = &mut result[(65 + 16)..(65 + 16 + msg.len())];
    cipher.apply_keystream(encryption_part);

    let hashed_part = &result[65..(65 + 16 + msg.len())];
    let digest = message_hmac(hashed_part, &auth_key, s2)?;
    result.extend_from_slice(&digest[..]);
    Ok(result)
}

pub fn decrypt(
    msg: &[u8],
    private_key: &SecretKey,
    s1: &[u8],
    s2: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let remote_public_key = PublicKey::from_slice(&msg[..65])?;
    let shared_secret = shared_secret(&remote_public_key, private_key);

    let (enc_key, auth_key) = derive_keys(shared_secret.as_ref(), s1)?;

    let digest = message_hmac(&msg[65..(msg.len() - 32)], &auth_key, s2)?;
    let expected: Hmac<sha256::Hash> = Hmac::from_slice(&msg[msg.len() - 32..])?;
    if expected.ne(&digest) {
        return Err(anyhow!(
            "Hash mismatch: {} but expected {}",
            digest.to_hex(),
            expected.to_hex()
        ));
    }

    let iv: GenericArray<u8, U16> = GenericArray::clone_from_slice(&msg[65..(65 + 16)]);
    let mut chiper = Aes128CTR::new(&enc_key, &iv);
    let mut decrypted = msg[(65 + 16)..(msg.len() - 32)].to_vec();
    chiper.apply_keystream(&mut decrypted);
    Ok(decrypted)
}

// derive two keys from given secret, one for encryption (size 16) another for hmac (size 32)
fn derive_keys(
    secret: &[u8],
    s1: &[u8],
) -> anyhow::Result<(GenericArray<u8, U16>, GenericArray<u8, U32>)> {
    let mut derived_key = [0u8; 16 * 2];
    concat_kdf::derive_key_into::<Sha256>(secret, s1, &mut derived_key)
        .map_err(|err| anyhow!("concat-KDF: {}", err))?;
    let second_part = Sha256::digest(&derived_key[16..]);

    let enc_key = GenericArray::clone_from_slice(&derived_key[..16]);
    let auth_key = GenericArray::clone_from_slice(second_part.as_ref());

    Ok((enc_key, auth_key))
}

fn message_hmac(msg: &[u8], km: &[u8], shared: &[u8]) -> anyhow::Result<Hmac<sha256::Hash>> {
    let mut mac_engine = HmacEngine::<sha256::Hash>::new(km);
    mac_engine.input(msg);
    mac_engine.input(shared);
    Ok(Hmac::from_engine(mac_engine))
}

// aligned with ethereum-go behaviour
fn shared_secret(public_key: &PublicKey, private_key: &SecretKey) -> Vec<u8> {
    let point = shared_secret_point(public_key, private_key);
    point[..32].to_vec()
}

#[cfg(test)]
mod tests {
    use crate::ecies::{decrypt, encrypt, shared_secret};
    use anyhow::anyhow;
    use secp256k1::ecdh::SharedSecret;
    use secp256k1::rand::rngs::OsRng;
    use secp256k1::{Secp256k1, SecretKey};
    use sha2::Sha256;

    #[test]
    fn test_kdf_derivation() -> anyhow::Result<()> {
        // data taken from eth ecies test suite
        let mut derived_key = [0u8; 16 * 2];
        concat_kdf::derive_key_into::<Sha256>(b"input", &[], &mut derived_key)
            .map_err(|err| anyhow!("concat-KDF: {}", err))?;

        Ok(assert_eq!(
            hex::encode(derived_key),
            "858b192fa2ed4395e2bf88dd8d5770d67dc284ee539f12da8bceaa45d06ebae0".to_string()
        ))
    }

    #[test]
    fn test_encryption_and_decryption_works() -> anyhow::Result<()> {
        let secp = Secp256k1::new();
        let mut rng = OsRng;
        let key = SecretKey::new(&mut rng);

        let encrypted = encrypt(b"much secret", &key.public_key(&secp), &[], b"mac auth key")?;
        let decrypted = decrypt(&encrypted, &key, &[], b"mac auth key")?;
        Ok(assert_eq!(
            hex::encode(b"much secret"),
            hex::encode(decrypted)
        ))
    }

    #[test]
    fn test_shared_secred_between_keys_works() -> anyhow::Result<()> {
        let secp = Secp256k1::new();
        // data taken from ethereum-go ecies tests
        let key1 = hex::decode("7ebbc6a8358bc76dd73ebc557056702c8cfc34e5cfcd90eb83af0347575fd2ad")?;
        let key2 = hex::decode("6a3d6396903245bba5837752b9e0348874e72db0c4e11e9c485a81b4ea4353b9")?;
        let expected =
            "167ccc13ac5e8a26b131c3446030c60fbfac6aa8e31149d0869f93626a4cdf62".to_string();

        let key1 = SecretKey::from_slice(&key1)?;
        let key2 = SecretKey::from_slice(&key2)?;

        let derived_secret = shared_secret(&key2.public_key(&secp), &key1);

        Ok(assert_eq!(expected, hex::encode(derived_secret)))
    }
}
