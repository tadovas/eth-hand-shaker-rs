/*

   Signature       [sigLen]byte   sigLen = 64 + 1 // 64 bytes ECDSA signature + 1 byte recovery id
   InitiatorPubkey [pubLen]byte   pubLen = 64 bytes
   Nonce           [shaLen]byte   shaLen = 32 bytes
   Version         uint   (value 4)
   ...
   trailing RPL which is ignored
*/

use rlp::{Decodable, DecoderError, Encodable, RlpStream, UntrustedRlp};
use std::fmt::Debug;

const VERSION: u32 = 4;

#[derive(Debug)]
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

#[derive(Debug)]
pub struct Header {
    pub capability_id: u32,
    pub context_id: u32,
}

impl Decodable for Header {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        Ok(Self {
            capability_id: rlp.val_at(0)?,
            context_id: rlp.val_at(1)?,
        })
    }
}

#[derive(Debug)]
pub struct Capability {
    pub name: String, // max 8 chars according to rplx
    pub version: u32,
}

impl Decodable for Capability {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        Ok(Self {
            name: rlp.val_at(0)?,
            version: rlp.val_at(1)?,
        })
    }
}

#[derive(Debug)]
pub struct Hello {
    pub proto_version: u32, // expect 5
    pub client_id: String,
    pub capabilities: Vec<Capability>,
    pub listen_port: u32, // 0 inidicates client is not listening
    pub node_id: Vec<u8>, // node's public key (64 bytes)
}

impl Decodable for Hello {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        Ok(Self {
            proto_version: rlp.val_at(0)?,
            client_id: rlp.val_at(1)?,
            capabilities: rlp.list_at(2)?,
            listen_port: rlp.val_at(3)?,
            node_id: rlp.val_at(4)?,
        })
    }
}

#[derive(Debug)]
pub struct Frame<T: Debug> {
    pub msg_id: u32,
    pub message: T,
}

impl<T: Decodable + Debug> Decodable for Frame<T> {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        let first_element_info = rlp.payload_info()?;
        let message_id = rlp.as_val()?;
        let data_rlp = UntrustedRlp::new(&rlp.as_raw()[first_element_info.total()..]);
        Ok(Self {
            msg_id: message_id,
            message: data_rlp.as_val()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::message::{Frame, Hello};
    use rlp::{Decodable, UntrustedRlp};

    #[test]
    fn test_hello_message_is_decoded_successfully() -> anyhow::Result<()> {
        // real world hello response from eth node (message-id (0x00 for hello) || [... hello data items...]
        let frame_data = hex::decode("80f89205b3476574682f76312e31312e302d756e737461626c652d66353366663066662f6c696e75782d616d6436342f676f312e31392e34d9c58365746842c58365746843c58365746844c684736e61700180b840301a16319c99079b7972909a8690f3a3a5db82e80d910c3cc225728f409ab92deb62da53132258beaee8562565d225f8f43332222dc6cf2f602aa6915dcb913f432548da21ca60cfaca44e")?;
        let rlp_data = UntrustedRlp::new(&frame_data);

        let hello_frame = Frame::<Hello>::decode(&rlp_data)?;
        println!("{:?}", hello_frame);
        assert_eq!(
            "Geth/v1.11.0-unstable-f53ff0ff/linux-amd64/go1.19.4".to_string(),
            hello_frame.message.client_id
        );
        Ok(())
    }
}
