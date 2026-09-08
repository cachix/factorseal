//! OpenSSH session-bind and host-bound authentication validation.
//! The final destination is authenticated by the data being signed. Forwarding
//! hops are delegations through host keys, not proof of the physical network path.

use base64::Engine as _;
use sha2::Digest as _;
use ssh_key::{Algorithm, HashAlg, PublicKey, Signature};

use super::{invalid, string};
use crate::vault::{SshDestination, VaultResult};

struct Binding {
    host_key: Vec<u8>,
    fingerprint: String,
    session_id: Vec<u8>,
    forwarding: bool,
}

#[derive(Default)]
pub(super) struct Bindings(Vec<Binding>);

impl Bindings {
    pub(super) fn bind(
        &mut self,
        host_key: &[u8],
        session_id: &[u8],
        signature: &[u8],
        forwarding: bool,
    ) -> VaultResult<()> {
        if self.0.len() >= 16
            || host_key.len() > 16 * 1024
            || signature.len() > 16 * 1024
            || !(16..=64).contains(&session_id.len())
            || self.0.last().is_some_and(|binding| !binding.forwarding)
            || self
                .0
                .iter()
                .any(|binding| binding.session_id == session_id)
        {
            return Err(invalid());
        }
        let signature_bytes = signature;
        let signature = Signature::try_from(signature_bytes).map_err(|_| invalid())?;
        if Vec::<u8>::try_from(signature.clone()).map_err(|_| invalid())? != signature_bytes {
            return Err(invalid());
        }
        // SHA-1 host proofs are not accepted.
        if matches!(
            signature.algorithm(),
            Algorithm::Rsa { hash: None } | Algorithm::Dsa
        ) {
            return Err(invalid());
        }
        let key = PublicKey::from_bytes(host_key).map_err(|_| invalid())?;
        if let ssh_key::public::KeyData::Certificate(certificate) = key.key_data() {
            if certificate.cert_type() != ssh_key::certificate::CertType::Host {
                return Err(invalid());
            }
            let now = super::unix_time()?;
            if now < certificate.valid_after()
                || now >= certificate.valid_before()
                || !certificate.critical_options().is_empty()
                || certificate.signature_key().is_certificate()
            {
                return Err(invalid());
            }
            // Integrity and time checks only: approval pins the complete host
            // certificate, rather than treating its self-declared CA as trusted.
            let encoded = certificate.to_bytes().map_err(|_| invalid())?;
            let signature_bytes =
                Vec::<u8>::try_from(certificate.signature().clone()).map_err(|_| invalid())?;
            let tbs_len = encoded
                .len()
                .checked_sub(4 + signature_bytes.len())
                .ok_or_else(invalid)?;
            super::crypto::verify(
                certificate.signature_key(),
                &encoded[..tbs_len],
                certificate.signature(),
            )?;
            super::crypto::verify(certificate.public_key(), session_id, &signature)?;
        } else {
            super::crypto::verify(key.key_data(), session_id, &signature)?;
        }
        // Hash the complete host key blob, including a certificate if supplied.
        // Certificate changes intentionally require fresh destination approval.
        let fingerprint = format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(sha2::Sha256::digest(host_key))
        );
        self.0.push(Binding {
            host_key: host_key.to_vec(),
            fingerprint,
            session_id: session_id.to_vec(),
            forwarding,
        });
        Ok(())
    }

    pub(super) fn is_forwarding(&self) -> bool {
        self.0.last().is_some_and(|binding| binding.forwarding)
    }

    pub(super) fn destination(
        &self,
        public_key: &[u8],
        mut data: &[u8],
        flags: u32,
    ) -> VaultResult<Option<SshDestination>> {
        let Some(last) = self.0.last() else {
            return Ok(None);
        };
        if last.forwarding || string(&mut data)? != last.session_id {
            return Err(invalid());
        }
        if take_byte(&mut data)? != 50 {
            return Err(invalid());
        }
        let user = std::str::from_utf8(string(&mut data)?).map_err(|_| invalid())?;
        if user.is_empty() || user.len() > 256 || user.chars().any(char::is_control) {
            return Err(invalid());
        }
        if string(&mut data)? != b"ssh-connection" {
            return Err(invalid());
        }
        let method = string(&mut data)?;
        let hostbound = method == b"publickey-hostbound-v00@openssh.com";
        if !hostbound && (method != b"publickey" || self.0.len() != 1) {
            return Err(invalid());
        }
        if take_byte(&mut data)? != 1 {
            return Err(invalid());
        }
        let algorithm = string(&mut data)?;
        let key = PublicKey::from_bytes(public_key).map_err(|_| invalid())?;
        let expected = match key.algorithm() {
            Algorithm::Rsa { .. } => match flags {
                2 => Algorithm::Rsa {
                    hash: Some(HashAlg::Sha256),
                },
                4 => Algorithm::Rsa {
                    hash: Some(HashAlg::Sha512),
                },
                _ => return Err(invalid()),
            },
            algorithm if flags == 0 => algorithm,
            _ => return Err(invalid()),
        };
        if algorithm != expected.as_str().as_bytes() || string(&mut data)? != public_key {
            return Err(invalid());
        }
        if hostbound && string(&mut data)? != last.host_key {
            return Err(invalid());
        }
        if !data.is_empty() {
            return Err(invalid());
        }
        Ok(Some(SshDestination {
            user: user.into(),
            host_keys: self
                .0
                .iter()
                .map(|binding| binding.fingerprint.clone())
                .collect(),
        }))
    }
}

fn take_byte(data: &mut &[u8]) -> VaultResult<u8> {
    let (value, tail) = data.split_first().ok_or_else(invalid)?;
    *data = tail;
    Ok(*value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::ssh_agent::put_string;
    use signature::Signer;
    use ssh_key::HashAlg;

    fn key(seed: u8) -> ssh_key::PrivateKey {
        ssh_key::private::Ed25519Keypair::from(ssh_key::private::Ed25519PrivateKey::from_bytes(
            &[seed; 32],
        ))
        .into()
    }
    fn bind(bindings: &mut Bindings, seed: u8, forwarding: bool) -> VaultResult<()> {
        let key = key(seed);
        let signature: Signature = key.try_sign(&[seed; 32]).unwrap();
        bindings.bind(
            &key.public_key().to_bytes().unwrap(),
            &[seed; 32],
            &Vec::<u8>::try_from(signature).unwrap(),
            forwarding,
        )
    }
    fn auth(session: u8, user: &[u8], public: &[u8], host: Option<&[u8]>) -> Vec<u8> {
        let mut data = Vec::new();
        put_string(&mut data, &[session; 32]).unwrap();
        data.push(50);
        put_string(&mut data, user).unwrap();
        put_string(&mut data, b"ssh-connection").unwrap();
        put_string(
            &mut data,
            if host.is_some() {
                b"publickey-hostbound-v00@openssh.com"
            } else {
                b"publickey"
            },
        )
        .unwrap();
        data.push(1);
        put_string(&mut data, b"ssh-ed25519").unwrap();
        put_string(&mut data, public).unwrap();
        if let Some(host) = host {
            put_string(&mut data, host).unwrap();
        }
        data
    }

    #[test]
    fn ssh_rsa_host_certificates_verify_both_ca_and_session_signatures() {
        let key =
            ssh_key::PrivateKey::from_openssh(include_str!("../../../tests/fixtures/ssh/rsa"))
                .unwrap()
                .decrypt("fixture-passphrase")
                .unwrap();
        let certificate = ssh_key::Certificate::from_openssh(include_str!(
            "../../../tests/fixtures/ssh/rsa-cert.pub"
        ))
        .unwrap();
        let host = certificate.to_bytes().unwrap();
        let signature =
            Vec::<u8>::try_from(super::super::crypto::sign(&key, &[7; 32], 4).unwrap()).unwrap();
        let mut bindings = Bindings::default();
        bindings.bind(&host, &[7; 32], &signature, false).unwrap();
        let mut tampered = host.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(
            Bindings::default()
                .bind(&tampered, &[7; 32], &signature, false)
                .is_err()
        );
        assert!(
            Bindings::default()
                .bind(&host, &[8; 32], &signature, false)
                .is_err()
        );
    }

    #[test]
    fn ssh_session_proofs_reject_tampering_repetition_and_invalid_order() {
        let mut bindings = Bindings::default();
        let key = key(1);
        let signature: Signature = key.try_sign(&[1; 32]).unwrap();
        let signature = Vec::<u8>::try_from(signature).unwrap();
        let public = key.public_key().to_bytes().unwrap();
        let mut trailing = signature.clone();
        trailing.push(0);
        assert!(bindings.bind(&public, &[1; 32], &trailing, true).is_err());
        assert!(bindings.bind(&public, &[2; 32], &signature, true).is_err());
        assert!(bindings.bind(&public, &[1; 32], &signature, true).is_ok());
        assert!(bindings.bind(&public, &[1; 32], &signature, false).is_err());
        assert!(bind(&mut bindings, 2, false).is_ok());
        assert!(bind(&mut bindings, 3, true).is_err());
        let mut bindings = Bindings::default();
        for seed in 1..=16 {
            bind(&mut bindings, seed, true).unwrap();
        }
        assert!(bind(&mut bindings, 17, true).is_err());
    }

    #[test]
    fn ssh_forwarding_requires_hostbound_authentication_for_the_exact_session_and_key() {
        let public = key(9).public_key().to_bytes().unwrap();
        let host = key(2).public_key().to_bytes().unwrap();
        let mut bindings = Bindings::default();
        assert_eq!(
            bindings.destination(&public, b"arbitrary data", 0).unwrap(),
            None
        );
        bind(&mut bindings, 1, true).unwrap();
        assert!(
            bindings
                .destination(&public, &auth(1, b"alice", &public, None), 0)
                .is_err()
        );
        bind(&mut bindings, 2, false).unwrap();
        let data = auth(2, b"alice", &public, Some(&host));
        let destination = bindings.destination(&public, &data, 0).unwrap().unwrap();
        assert_eq!(destination.user, "alice");
        assert_eq!(
            destination.host_keys,
            [
                key(1).fingerprint(HashAlg::Sha256).to_string(),
                key(2).fingerprint(HashAlg::Sha256).to_string()
            ]
        );
        for invalid in [
            auth(2, b"alice", &public, None),
            auth(1, b"alice", &public, Some(&host)),
            auth(2, b"alice", &public, Some(&public)),
            auth(2, b"alice", &host, Some(&host)),
            auth(2, b"", &public, Some(&host)),
            auth(2, b"alice\nroot", &public, Some(&host)),
            [data.as_slice(), &[0]].concat(),
        ] {
            assert!(bindings.destination(&public, &invalid, 0).is_err());
        }
        assert!(bindings.destination(&public, &data, 2).is_err());
    }

    #[test]
    fn ssh_local_session_accepts_standard_userauth_but_never_raw_signing() {
        let public = key(9).public_key().to_bytes().unwrap();
        let mut bindings = Bindings::default();
        bind(&mut bindings, 1, false).unwrap();
        assert!(
            bindings
                .destination(&public, &auth(1, b"alice", &public, None), 0)
                .unwrap()
                .is_some()
        );
        assert!(bindings.destination(&public, b"arbitrary data", 0).is_err());
    }
}
