#[cfg(feature = "vault-store")]
mod grant;
#[cfg(feature = "vault-store")]
mod lease;
#[cfg(feature = "vault-store")]
mod service;
mod wire;

#[cfg(feature = "vault-store")]
pub use grant::GrantPermission;
#[cfg(feature = "vault-store")]
pub use lease::UnsealLeasePolicy;
#[cfg(feature = "vault-store")]
pub use service::VaultService;
pub use wire::{
    CallerIdentity, CallerPlatform, MAX_PERMISSION_WAIT_MS, Permission, PermissionChange,
    PermissionOperation, PermissionPrincipal, PermissionState, RequestId, VaultAction,
    VaultApplicationContext, VaultClient, VaultInteractionReference, VaultMutation, VaultRequest,
    VaultResponse, VaultResponseBody, VaultResponseError, VaultResponseErrorCode, WireSecret,
    WireSecretAddress,
};

#[cfg(test)]
mod redaction_tests {
    use super::*;

    /// Every enclosing type derives `Debug`, so the redaction has to hold
    /// through a whole request and response, not only on the leaf type.
    #[test]
    fn debug_output_never_carries_secret_bytes() {
        const NEEDLE: &[u8] = b"needle-secret-value";

        let request = VaultRequest::new(VaultAction::Mutate {
            namespace: b"secretspec".to_vec(),
            mutations: vec![VaultMutation::Put {
                address: WireSecretAddress::new("demo/default/TOKEN", None),
                value: WireSecret::new(NEEDLE.to_vec()),
                evict_at: None,
            }],
        })
        .unwrap();
        let response = VaultResponse::success(
            request.request_id(),
            VaultResponseBody::Secret {
                value: Some(WireSecret::new(NEEDLE.to_vec())),
            },
        );

        for rendered in [
            format!("{:?}", WireSecret::new(NEEDLE.to_vec())),
            format!("{request:?}"),
            format!("{response:?}"),
        ] {
            assert!(
                !rendered.contains(str::from_utf8(NEEDLE).unwrap()),
                "secret bytes appeared in Debug output: {rendered}"
            );
            assert!(rendered.contains("REDACTED"));
        }
    }
}
