use crate::crypto::{init_keccak256_hasher, keccak256_hash, Aes256CTR, HashMac};
use crate::ecies::{decrypt, ECIES_OVERHEAD};
use crate::message::{AuthRespV4, Disconnect, Frame, Header};
use crate::{ecies, message};
use aes::cipher::consts::U32;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::KeyInit;
use aes::cipher::KeyIvInit;
use aes::Aes256;
use anyhow::anyhow;
use bytes::BufMut;
use ctr::cipher::StreamCipher;
use rlp::{Decodable, Encodable, UntrustedRlp};
use secp256k1::ecdh::shared_secret_point;
use secp256k1::ecdsa::RecoverableSignature;
use secp256k1::rand::rngs::OsRng;
use secp256k1::rand::RngCore;
use secp256k1::{Message, SecretKey};
use secp256k1::{PublicKey, Secp256k1};
use std::fmt::Debug;
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
    let mut auth_packet = Vec::with_capacity(auth_encrypted.len() + 2);
    // we need full packet (with two bytes of size to feed into hasher later)
    auth_packet.put_u16(auth_message_size);
    auth_packet.extend_from_slice(&auth_encrypted);
    conn.write_all(&auth_packet).await?;
    conn.flush().await?;

    // read the response
    let res = conn.read_u16().await?;
    let mut auth_response_encrypted = Vec::with_capacity((res + 2) as usize);
    auth_response_encrypted.put_u16(res);
    conn.read_buf(&mut auth_response_encrypted).await?;

    let auth_resp_bytes = decrypt(
        &auth_response_encrypted[2..],
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

    let egress_hasher = init_keccak256_hasher(&mac_secret, &auth_resp.nonce, &auth_packet);
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

fn from_u24_be(val: u32) -> Vec<u8> {
    val.to_be_bytes()[1..].to_vec()
}

pub struct Session<C> {
    conn: C,
    encoder: Aes256CTR,
    decoder: Aes256CTR,
    ingress_hasher: HashMac,
    egress_hasher: HashMac,
}

impl<C: AsyncRead + AsyncWrite + Unpin> Session<C> {
    pub async fn read_frame<T: Decodable + Debug>(&mut self) -> anyhow::Result<Frame<T>> {
        let mut frame_header = [0u8; 32];
        self.conn.read_exact(frame_header.as_mut()).await?;
        let received_mac = &frame_header[16..];
        let computed_mac = self
            .ingress_hasher
            .compute_header_mac(&frame_header[..16])?;
        if !computed_mac.eq(received_mac) {
            return Err(anyhow!(
                "Header mac mismatch. Expected: {} received: {}",
                hex::encode(computed_mac),
                hex::encode(received_mac)
            ));
        }
        let payload_to_decrypt = &mut frame_header[..16];
        self.decoder.apply_keystream(payload_to_decrypt);
        // we don't need mutability anymore - reborrow
        let frame_header_data = &frame_header[..16];

        // try to decode header RLP just for sanity check
        let _ = Header::decode(&UntrustedRlp::new(&frame_header_data[3..]))?;

        let frame_size = to_u24_be(frame_header_data)?;

        let padded_size: usize = {
            let padding = frame_size % 16;
            if padding > 0 {
                frame_size + (16 - padding)
            } else {
                frame_size
            }
        } as usize;
        let mut frame_data = Vec::with_capacity(padded_size + 16); // additional 16 bytes is frame mac
        self.conn.read_buf(&mut frame_data).await?;
        let received = &frame_data[padded_size..];
        let computed = self
            .ingress_hasher
            .compute_frame_mac(&frame_data[..padded_size])?;
        if !computed.eq(received) {
            return Err(anyhow!(
                "Frame mac mismatch. Expected: {} received: {}",
                hex::encode(computed),
                hex::encode(received)
            ));
        }
        self.decoder.apply_keystream(&mut frame_data[..padded_size]);
        //println!("data: {}", hex::encode(&frame_data));
        let rlp_stream = UntrustedRlp::new(&frame_data[..padded_size]);
        Ok(Frame::<T>::decode(&rlp_stream)?)
    }

    pub async fn write_frame<T: Encodable + Debug>(
        &mut self,
        frame: &Frame<T>,
    ) -> anyhow::Result<()> {
        let mut frame_data = frame.rlp_bytes().to_vec();
        let frame_data_size = frame_data.len();
        let padding = frame_data_size % 16;
        if padding > 0 {
            frame_data.put_bytes(0, 16 - padding)
        }

        // data is ready
        let mut header: Vec<u8> = Vec::with_capacity(16);
        header.extend_from_slice(&from_u24_be(frame_data_size as u32));
        header.extend_from_slice(
            &Header {
                capability_id: 0,
                context_id: 0,
            }
            .rlp_bytes(),
        );
        let padding = 16 - header.len();
        if padding > 0 {
            header.put_bytes(0, padding)
        }
        self.encoder.apply_keystream(&mut header[..]);
        self.conn.write_all(&header).await?;
        self.conn
            .write_all(&self.egress_hasher.compute_header_mac(&header[..])?)
            .await?;

        self.encoder.apply_keystream(&mut frame_data[..]);
        self.conn.write_all(&frame_data).await?;
        self.conn
            .write_all(&self.egress_hasher.compute_frame_mac(&frame_data[..])?)
            .await?;
        self.conn.flush().await?;
        Ok(())
    }

    pub async fn shutdown(mut self) -> anyhow::Result<()> {
        self.write_frame(&Disconnect { reason: 0x8 }.into()).await?;
        self.conn.shutdown().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::session::{from_u24_be, to_u24_be};

    #[test]
    fn u24_conversion_test() -> anyhow::Result<()> {
        let val = to_u24_be(&[1u8, 2u8, 3u8])?;
        assert_eq!(0x010203u32, val);
        let vec_val = from_u24_be(val);
        Ok(assert_eq!([1u8, 2u8, 3u8].to_vec(), vec_val))
    }
}
