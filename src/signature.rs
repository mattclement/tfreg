use std::{io::Write, time::Duration};

use anyhow::Result;
use sequoia_openpgp::{
    cert::{CertBuilder, CipherSuite},
    policy::StandardPolicy,
    serialize::{
        stream::{Message, Signer},
        SerializeInto,
    },
};
use tracing::{debug, instrument};

pub struct GPGSigner {
    cert: sequoia_openpgp::Cert,
}

impl GPGSigner {
    #[instrument(name = "GPGSigner::new")]
    pub fn new() -> Result<Self> {
        debug!("Generating GPG signing key");
        let (cert, _) = CertBuilder::general_purpose(CipherSuite::RSA3k, Some("tfreg@localhost"))
            .set_validity_period(Duration::from_secs(60 * 60 * 24 * 7 * 52))
            .generate()?;
        Ok(Self { cert })
    }

    pub fn fingerprint(&self) -> String {
        self.cert.fingerprint().to_hex()
    }

    pub fn ascii_armor(&self) -> Result<String> {
        Ok(String::from_utf8(self.cert.armored().to_vec()?)?)
    }

    #[instrument(skip_all, name = "sign")]
    pub fn sign(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let keypair = self
            .cert
            .keys()
            .unencrypted_secret()
            .with_policy(&StandardPolicy::new(), None)
            .supported()
            .alive()
            .revoked(false)
            .for_signing()
            .next()
            .unwrap()
            .key()
            .clone()
            .into_keypair()?;
        let mut buf = vec![];
        let message = Message::new(&mut buf);
        let mut signer = Signer::new(message, keypair).detached().build()?;
        signer.write_all(plaintext)?;
        signer.finalize()?;
        Ok(buf)
    }
}
