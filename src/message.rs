/*

   Signature       [sigLen]byte   sigLen = 64 + 1 // 64 bytes ECDSA signature + 1 byte recovery id
   InitiatorPubkey [pubLen]byte   pubLen = 64 bytes
   Nonce           [shaLen]byte   shaLen = 32 bytes
   Version         uint   (value 4)
   ...
   trailing RPL which is ignored
*/

use rlp::{Decodable, DecoderError, Encodable, RlpStream, UntrustedRlp};
use secp256k1::PublicKey;

const VERSION: u32 = 4;

pub struct AuthMsgV4 {
    pub signature: [u8; 65],
    pub pub_key: [u8; 64],
    pub nonce: [u8; 32],
}

impl Encodable for AuthMsgV4 {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(4)
            .append(&self.signature.as_slice())
            .append(&self.pub_key.as_slice())
            .append(&self.nonce.as_slice())
            .append(&VERSION);
    }
}

#[derive(Debug)]
pub struct AuthRespV4 {
    pub pub_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub version: u32,
}

impl Decodable for AuthRespV4 {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        Ok(AuthRespV4 {
            pub_key: rlp.val_at(0)?,
            nonce: rlp.val_at(1)?,
            version: rlp.val_at(2)?,
        })
    }
}
