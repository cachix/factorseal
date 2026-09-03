//! Serde helpers shared by persisted records and the wire protocol.

/// Secret bytes are stored and transmitted as base64 text rather than serde's
/// default JSON integer array, which is three to four times larger.
pub(crate) mod base64_bytes {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use zeroize::Zeroizing;

    pub(crate) fn serialize<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        let encoded = Zeroizing::new(STANDARD.encode(value));
        encoded.as_str().serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>, T: From<Vec<u8>>>(
        deserializer: D,
    ) -> Result<T, D::Error> {
        let encoded = Zeroizing::new(String::deserialize(deserializer)?);
        STANDARD
            .decode(encoded.as_bytes())
            .map(T::from)
            .map_err(serde::de::Error::custom)
    }
}
