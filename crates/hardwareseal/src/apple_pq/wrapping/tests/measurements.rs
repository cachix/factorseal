//! Opt-in measurements on the same physical Mac using synthetic 32-byte roots.
use super::*;
use crate::{Backend, Protector};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::time::{Duration, Instant};

struct Scratch(Protector);
impl Drop for Scratch {
    fn drop(&mut self) {
        // Only this run's random label is ever removed, including on failure.
        let _ = self.0.delete();
    }
}

fn report(backend: &str, operation: &str, samples: &mut [Duration], bytes: usize) {
    let first = samples[0].as_micros();
    samples.sort_unstable();
    eprintln!(
        "{backend},{operation},{},{first},{},{},{},{bytes}",
        samples.len(),
        samples[(samples.len() - 1) / 2].as_micros(),
        samples[(samples.len() * 95).div_ceil(100) - 1].as_micros(),
        samples.last().unwrap().as_micros(),
    );
}

#[test]
#[ignore = "requires physical macOS 26+ Secure Enclave and provisioned Keychain access"]
fn compare_mlkem_and_keychain_wrapping_costs() -> Result<(), Error> {
    if !cfg!(target_os = "macos") {
        return Err(Error::NotAvailable);
    }
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce).map_err(|error| Error::Hardware(error.to_string()))?;
    let label = format!("hardwareseal-pq-measure-{}", URL_SAFE_NO_PAD.encode(nonce));
    let policy = AccessPolicy::None;
    let root = Zeroizing::new([0x5a; 32]);
    let keychain = Scratch(Protector::open(&label, policy)?);
    assert_eq!(keychain.0.backend(), Backend::AppleKeychain);
    let start = Instant::now();
    let kem = MlKem768WrappingKey::generate(policy)?;
    eprintln!("mlkem_key_generation_us={}", start.elapsed().as_micros());
    let (mut keychain_seal, mut keychain_unseal) = (Vec::new(), Vec::new());
    let (mut kem_seal, mut kem_unseal) = (Vec::new(), Vec::new());
    let (mut keychain_bytes, mut kem_bytes) = (0, 0);
    for _ in 0..20 {
        let start = Instant::now();
        let envelope = keychain.0.seal(&root[..])?;
        keychain_seal.push(start.elapsed());
        keychain_bytes = envelope.len();
        let reopened = Protector::open(&label, policy)?;
        let start = Instant::now();
        let plain = reopened.unseal(&envelope)?;
        keychain_unseal.push(start.elapsed());
        assert_eq!(&*plain, &root[..]);

        let start = Instant::now();
        let envelope = kem.seal(&label, &root[..])?;
        kem_seal.push(start.elapsed());
        kem_bytes = envelope.len();
        let start = Instant::now();
        let plain = MlKem768WrappingKey::unseal(&label, policy, &envelope)?;
        kem_unseal.push(start.elapsed());
        assert_eq!(&*plain, &root[..]);
    }
    keychain.0.delete()?;
    eprintln!("backend,operation,samples,first_us,p50_us,p95_us,max_us,envelope_bytes");
    report("keychain", "seal", &mut keychain_seal, keychain_bytes);
    report("keychain", "unseal", &mut keychain_unseal, keychain_bytes);
    report("mlkem768", "seal", &mut kem_seal, kem_bytes);
    report("mlkem768", "unseal", &mut kem_unseal, kem_bytes);
    Ok(())
}
