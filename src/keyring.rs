//! Credential-oriented interface implemented by Factorseal vault clients.

use crate::{
    VaultAction, VaultClient, VaultError, VaultRequest, VaultResponseBody, VaultResponseErrorCode,
    WireSecret, WireSecretAddress,
};

/// Errors returned through the keyring interface.
#[derive(Debug, thiserror::Error)]
pub enum KeyringError {
    #[error(transparent)]
    Vault(#[from] VaultError),

    #[error("vault request failed ({code:?}): {message}")]
    Request {
        code: VaultResponseErrorCode,
        message: String,
    },

    #[error("vault returned an unexpected response to a keyring operation")]
    UnexpectedResponse,
}

pub type KeyringResult<T> = std::result::Result<T, KeyringError>;

/// Durable credential operations exposed by a Factorseal vault.
///
/// Native [`VaultClient`] implementations receive this interface through the
/// blanket implementation below. Vault lifecycle and cache operations remain
/// on the lower-level vault protocol because they are not keyring operations.
pub trait Keyring: Send + Sync {
    fn get(
        &self,
        namespace: &[u8],
        address: &WireSecretAddress,
    ) -> KeyringResult<Option<WireSecret>>;

    fn set(
        &self,
        namespace: &[u8],
        address: &WireSecretAddress,
        value: &[u8],
    ) -> KeyringResult<()> {
        self.set_with_expiry(namespace, address, value, None)
    }

    fn set_with_expiry(
        &self,
        namespace: &[u8],
        address: &WireSecretAddress,
        value: &[u8],
        evict_at: Option<u64>,
    ) -> KeyringResult<()>;

    fn delete(&self, namespace: &[u8], address: &WireSecretAddress) -> KeyringResult<bool>;

    fn clear(&self, namespace: &[u8]) -> KeyringResult<usize>;
}

impl<T: VaultClient + ?Sized> Keyring for T {
    fn get(
        &self,
        namespace: &[u8],
        address: &WireSecretAddress,
    ) -> KeyringResult<Option<WireSecret>> {
        match request(
            self,
            VaultAction::Get {
                namespace: namespace.to_vec(),
                address: address.clone(),
            },
        )? {
            VaultResponseBody::Secret { value } => Ok(value),
            _ => Err(KeyringError::UnexpectedResponse),
        }
    }

    fn set_with_expiry(
        &self,
        namespace: &[u8],
        address: &WireSecretAddress,
        value: &[u8],
        evict_at: Option<u64>,
    ) -> KeyringResult<()> {
        match request(
            self,
            VaultAction::Put {
                namespace: namespace.to_vec(),
                address: address.clone(),
                value: WireSecret::new(value.to_vec()),
                evict_at,
            },
        )? {
            VaultResponseBody::Stored => Ok(()),
            _ => Err(KeyringError::UnexpectedResponse),
        }
    }

    fn delete(&self, namespace: &[u8], address: &WireSecretAddress) -> KeyringResult<bool> {
        match request(
            self,
            VaultAction::Delete {
                namespace: namespace.to_vec(),
                address: address.clone(),
            },
        )? {
            VaultResponseBody::Deleted { existed } => Ok(existed),
            _ => Err(KeyringError::UnexpectedResponse),
        }
    }

    fn clear(&self, namespace: &[u8]) -> KeyringResult<usize> {
        match request(
            self,
            VaultAction::Clear {
                namespace: namespace.to_vec(),
            },
        )? {
            VaultResponseBody::Cleared { entries } => Ok(entries),
            _ => Err(KeyringError::UnexpectedResponse),
        }
    }
}

fn request<T: VaultClient + ?Sized>(
    client: &T,
    action: VaultAction,
) -> KeyringResult<VaultResponseBody> {
    let request = VaultRequest::new(action)?;
    let response = client.request(&request)?;
    response.result.map_err(|error| KeyringError::Request {
        code: error.code,
        message: error.message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestVaultClient;

    impl VaultClient for TestVaultClient {
        fn request(&self, request: &VaultRequest) -> crate::VaultResult<crate::VaultResponse> {
            let body = match &request.action {
                VaultAction::Get { .. } => VaultResponseBody::Secret {
                    value: Some(WireSecret::new(b"secret".to_vec())),
                },
                VaultAction::Put { .. } => VaultResponseBody::Stored,
                VaultAction::Delete { .. } => VaultResponseBody::Deleted { existed: true },
                VaultAction::Clear { .. } => VaultResponseBody::Cleared { entries: 1 },
                _ => panic!("keyring emitted a non-keyring vault action"),
            };
            Ok(crate::VaultResponse::success(request.request_id(), body))
        }
    }

    #[test]
    fn vault_clients_implement_the_keyring_interface() {
        let client = TestVaultClient;
        let address = WireSecretAddress::new("github", Some("token".to_owned()));

        client.set(b"default", &address, b"secret").unwrap();
        let value = client.get(b"default", &address).unwrap().unwrap();
        assert_eq!(value.expose(), b"secret");
        assert!(client.delete(b"default", &address).unwrap());
        assert_eq!(client.clear(b"default").unwrap(), 1);
    }
}
