use crate::ecies::{decrypt, ECIES_OVERHEAD};
use crate::message::AuthRespV4;
use crate::{ecies, message};
use rlp::{Decodable, Encodable, UntrustedRlp};
use secp256k1::ecdh::shared_secret_point;
use secp256k1::ecdsa::RecoverableSignature;
use secp256k1::rand::rngs::OsRng;
use secp256k1::rand::RngCore;
use secp256k1::{Message, SecretKey};
use secp256k1::{PublicKey, Secp256k1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub struct Session {}

pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    mut conn: S,
    remote_public_key: &PublicKey,
    local_secret_key: &SecretKey,
) -> anyhow::Result<Session> {
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
    let mut vec = Vec::with_capacity(res as usize);
    conn.read_buf(&mut vec).await?;

    let auth_resp_bytes = decrypt(&vec, local_secret_key, &res.to_be_bytes())?;

    let rlp_stream = UntrustedRlp::new(&auth_resp_bytes);
    let auth_resp = AuthRespV4::decode(&rlp_stream)?;

    println!("Auth resp: {:?}", auth_resp);
    // now to handle all the secrecy and create hmac and encrypter for outgoing data, and hmac and decrypter for incoming data
    Ok(Session {})
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
