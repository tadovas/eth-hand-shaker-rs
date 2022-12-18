/*

   Signature       [sigLen]byte   sigLen = 64 + 1 // 64 bytes ECDSA signature + 1 byte recovery id
   InitiatorPubkey [pubLen]byte   pubLen = 64 bytes
   Nonce           [shaLen]byte   shaLen = 32 bytes
   Version         uint   (value 4)
   ...
   trailing RPL which is ignored
*/

use rlp::{Encodable, RlpStream};

const VERSION: u32 = 4;

pub struct AuthMsgV4 {
    pub signature: [u8; 65],
    pub pub_key: [u8; 64],
    pub nonce: [u8; 32],
}

impl Default for AuthMsgV4 {
    fn default() -> Self {
        Self {
            signature: [4; 65],
            pub_key: [5; 64],
            nonce: [6; 32],
        }
    }
}

const PADDING: [u8; 150] = [0xFE; 150];

impl Encodable for AuthMsgV4 {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(4)
            .append(&self.signature.as_slice())
            .append(&self.pub_key.as_slice())
            .append(&self.nonce.as_slice())
            .append(&VERSION)
            // everything is ignored by handshake beyond this point but we need some addtional data to make message big enough as per EIP-8
            .append(&PADDING.as_slice());
    }
}
