use displaydoc::Display;
use secp256k1::PublicKey;
use std::str::FromStr;
use thiserror::Error;
use url::Url;

#[derive(Error, Debug, Display)]
pub enum Error {
    /// invalid URL schema: {0}, enode expected
    InvalidSchema(String),
    /// host missing
    HostMissing,
    /// port missing
    PortMissing,
    /// username as public key: {0}
    PublicKeyInvalid(#[source] secp256k1::Error),
    /// invalid url: {0}
    InvalidUrl(#[source] url::ParseError),
}

#[derive(Debug, Clone)]
pub struct Address {
    pub host: String,
    pub port: u16,
    pub public_key: PublicKey,
}

impl TryFrom<Url> for Address {
    type Error = Error;

    fn try_from(value: Url) -> Result<Self, Self::Error> {
        if value.scheme() != "enode" {
            return Err(Error::InvalidSchema(value.scheme().to_string()));
        }
        // public key parser expects 04 char for uncompressed key indication
        let public_key_str = &format!("04{}", value.username());
        Ok(Self {
            host: value.host().ok_or(Error::HostMissing)?.to_string(),
            port: value.port().ok_or(Error::PortMissing)?,
            public_key: PublicKey::from_str(public_key_str).map_err(Error::PublicKeyInvalid)?,
        })
    }
}

impl FromStr for Address {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Url::try_from(s)
            .map_err(Error::InvalidUrl)
            .and_then(Address::try_from)
    }
}

#[cfg(test)]
mod tests {
    use crate::node::Address;
    use std::str::FromStr;

    const NODE_URL: &str = "enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666@18.138.108.67:30303";

    #[test]
    fn test_node_address_is_successfully_parsed_from_url() {
        let res = Address::from_str(&NODE_URL).expect("should not fail");
        assert_eq!(
            (res.host, res.port),
            ("18.138.108.67".to_string(), 30303u16)
        )
    }
}
