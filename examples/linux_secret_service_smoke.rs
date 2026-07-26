//! Manual interoperability check for a running `factorseal serve`.

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::HashMap;

    use dbus_secret_service::{EncryptionType, SecretService};

    let service = SecretService::connect(EncryptionType::Dh)?;
    let collection = service.get_default_collection()?;
    let attributes = HashMap::from([
        ("target", "default"),
        ("service", "factorseal-smoke-test"),
        ("username", "round-trip"),
    ]);
    let item = collection.create_item(
        "FactorSeal interoperability check",
        attributes.clone(),
        b"secret-service-round-trip",
        true,
        "application/octet-stream",
    )?;
    drop(item);
    drop(collection);
    drop(service);

    // Exercise the common keyring-library behavior of reconnecting for the
    // next API call. The process-scoped grant should survive the reconnect.
    let service = SecretService::connect(EncryptionType::Dh)?;
    let mut result = service.search_items(attributes)?;
    assert!(result.locked.is_empty());
    assert_eq!(result.unlocked.len(), 1);
    let item = result.unlocked.swap_remove(0);
    assert_eq!(item.get_secret()?, b"secret-service-round-trip");
    item.delete()?;
    println!("FactorSeal Secret Service round trip succeeded");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("this example requires Linux");
}
