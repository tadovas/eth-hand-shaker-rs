use crate::crypto::{init_keccak256_hasher, keccak256_hash, Aes256CTR, HashMac};
use crate::ecies::{decrypt, ECIES_OVERHEAD};
use crate::message::{AuthRespV4, Header};
use crate::{ecies, message};
use aes::cipher::consts::U32;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::KeyInit;
use aes::cipher::KeyIvInit;
use aes::Aes256;
use anyhow::anyhow;
use ctr::cipher::StreamCipher;
use rlp::{Decodable, Encodable, UntrustedRlp};
use secp256k1::ecdh::shared_secret_point;
use secp256k1::ecdsa::RecoverableSignature;
use secp256k1::rand::rngs::OsRng;
use secp256k1::rand::RngCore;
use secp256k1::{Message, SecretKey};
use secp256k1::{PublicKey, Secp256k1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn handshake<C: AsyncRead + AsyncWrite + Unpin>(
    mut conn: C,
    remote_public_key: &PublicKey,
    local_secret_key: &SecretKey,
) -> anyhow::Result<Session<C>> {
    let secp = Secp256k1::new();
    let mut rng = OsRng;

    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    let token = shared_secret_point(remote_public_key, local_secret_key);

    // xor nonce ^ first 32 bytes of token
    let to_sign: Vec<u8> = nonce
        .iter()
        .zip(token.iter())
        .map(|v| *v.0 ^ *v.1)
        .collect();

    let private_ethemeral_key = SecretKey::new(&mut rng);
    let signature =
        secp.sign_ecdsa_recoverable(&Message::from_slice(&to_sign)?, &private_ethemeral_key);

    let auth_message = message::AuthMsgV4 {
        signature: make_signature_with_recovery_id_as_byte(&signature),
        pub_key: cut_first_byte_of_pub_key(&local_secret_key.public_key(&secp)),
        nonce,
    };

    let mut auth_message_bytes = auth_message.rlp_bytes().to_vec();
    // append some zeros to make message distinguishable from non EIP-8 (required by eth)
    auth_message_bytes.extend_from_slice(&[0u8; 150]);
    let auth_message_size: u16 = (auth_message_bytes.len() + ECIES_OVERHEAD) as u16;

    let auth_encrypted = ecies::encrypt(
        auth_message_bytes.as_ref(),
        remote_public_key,
        &auth_message_size.to_be_bytes(),
    )?;

    conn.write_u16(auth_message_size).await?;
    conn.write_all(&auth_encrypted).await?;
    conn.flush().await?;

    // read the response
    let res = conn.read_u16().await?;
    let mut auth_response_encrypted = Vec::with_capacity(res as usize);
    conn.read_buf(&mut auth_response_encrypted).await?;

    let auth_resp_bytes = decrypt(
        &auth_response_encrypted,
        local_secret_key,
        &res.to_be_bytes(),
    )?;

    let rlp_stream = UntrustedRlp::new(&auth_resp_bytes);
    let auth_resp = AuthRespV4::decode(&rlp_stream)?;

    // now to handle all the secrecy and create hmac and encrypter for outgoing data, and hmac and decrypter for incoming data
    // this 64 bytes + prefix thing is really annoying, eth protocol sends 64 bytes of public key
    // but library expects 65 (0x04 byte as prefix for uncompressed indication)
    let mut remote_ephemeral_pub_key: Vec<u8> = Vec::with_capacity(65);
    remote_ephemeral_pub_key.push(0x04);
    remote_ephemeral_pub_key.extend_from_slice(auth_resp.pub_key.as_slice());
    let remote_ephemeral_pub_key = PublicKey::from_slice(&remote_ephemeral_pub_key)?;

    let shared_static_secret =
        ecies::shared_secret(&remote_ephemeral_pub_key, &private_ethemeral_key);
    let shared_secret = keccak256_hash(
        &shared_static_secret,
        &keccak256_hash(&auth_resp.nonce, &nonce),
    );
    let aes_secret = keccak256_hash(&shared_static_secret, &shared_secret);
    let mac_secret = keccak256_hash(&shared_static_secret, &aes_secret);

    let egress_hasher = init_keccak256_hasher(&mac_secret, &auth_resp.nonce, &auth_encrypted);
    let ingress_hasher = init_keccak256_hasher(&mac_secret, &nonce, &auth_response_encrypted);

    // all zeroes IV intentional because according to eth - ephemeral keys are used for AES
    let zero_iv = [0u8; 16];
    let mac_key: GenericArray<u8, U32> = GenericArray::clone_from_slice(&mac_secret);
    let aes_key: GenericArray<u8, U32> = GenericArray::clone_from_slice(&aes_secret);
    Ok(Session {
        conn,
        // eth creates aes instance and passes it to CRT streams of both encoding and decoding
        // not sure if intention was to have a single state shared by enc dec or if instance is cloned on assignation
        // lets assume instance is not shared (that would be crazy from asynchronous read/write perspective in eth)
        encoder: Aes256CTR::new(&aes_key, &zero_iv.into()),
        decoder: Aes256CTR::new(&aes_key, &zero_iv.into()),
        egress_hasher: HashMac::new(Aes256::new(&mac_key), egress_hasher),
        ingress_hasher: HashMac::new(Aes256::new(&mac_key), ingress_hasher),
    })
}

fn make_signature_with_recovery_id_as_byte(signature: &RecoverableSignature) -> [u8; 65] {
    let (recovery_id, signature_bytes) = signature.serialize_compact();
    let mut res = [0u8; 65];
    for (dst, val) in res.iter_mut().zip(signature_bytes.iter()) {
        *dst = *val;
    }
    res[64] = recovery_id.to_i32() as u8;
    res
}

fn cut_first_byte_of_pub_key(public_key: &PublicKey) -> [u8; 64] {
    let mut res = [0u8; 64];
    for (dst, val) in res
        .iter_mut()
        .zip(public_key.serialize_uncompressed()[1..].iter())
    {
        *dst = *val;
    }
    res
}

// take first 3 bytes and craft 24 bit unsigned integer (return as u32)
fn to_u24_be(slice: &[u8]) -> anyhow::Result<u32> {
    if slice.len() < 3 {
        return Err(anyhow!("at least 3 bytes slice expected"));
    }
    Ok(slice
        .iter()
        .take(3)
        .fold(0u32, |acc, item| (acc << 8) | *item as u32))
}

pub struct Session<C> {
    conn: C,
    encoder: Aes256CTR,
    decoder: Aes256CTR,
    ingress_hasher: HashMac,
    egress_hasher: HashMac,
}

impl<C: AsyncRead + AsyncWrite + Unpin> Session<C> {
    pub async fn read_message(&mut self) -> anyhow::Result<()> {
        let mut frame_header = [0u8; 32];
        self.conn.read_exact(frame_header.as_mut()).await?;
        // TODO - hmac check first before any interpretations
        let payload_to_decrypt = &mut frame_header[..16];
        self.decoder.apply_keystream(payload_to_decrypt);
        // we don't need mutability anymore - reborrow
        let frame_header_data = &frame_header[..16];
        println!("Decrypted frame header: {}", hex::encode(frame_header_data));
        let header = Header::decode(&UntrustedRlp::new(&frame_header_data[3..]))?;
        println!("Header: {:?}", header);

        let frame_size = to_u24_be(frame_header_data)?;
        println!("Frame data size: {}", frame_size);

        let padded_size: usize = {
            let padding = frame_size % 16;
            if padding > 0 {
                frame_size + (16 - padding)
            } else {
                frame_size
            }
        } as usize;
        let mut frame_data = Vec::with_capacity(padded_size);
        self.conn.read_exact(&mut frame_data).await?;
        println!("Frame encrypted data: {}", hex::encode(&frame_data));
        self.decoder
            .apply_keystream(&mut frame_data[..(padded_size - 16)]);
        println!("Frame data: {}", hex::encode(&frame_data));
        Ok(())
    }
}
