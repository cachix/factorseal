use factorseal::WireSecretAddress;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use secretspec_ipc::error::{ErrorKind, RpcError};
use secretspec_ipc::protocol::provider::{Address, Coordinates};
use secretspec_ipc::server::RpcResult;

pub(super) fn coordinates(address: Address) -> RpcResult<Coordinates> {
    let coordinates = match address {
        Address::Convention {
            project,
            profile,
            key,
        } => {
            let encode = |value: &str| utf8_percent_encode(value, NON_ALPHANUMERIC).to_string();
            Coordinates {
                item: format!(
                    "v1/{}/{}/{}",
                    encode(&project),
                    encode(&profile),
                    encode(&key)
                ),
                field: None,
                vault: None,
                section: None,
                version: None,
            }
        }
        Address::Native { coordinates } => coordinates,
    };
    if coordinates.vault.is_some() || coordinates.section.is_some() || coordinates.version.is_some()
    {
        return Err(RpcError::new(ErrorKind::InvalidParams));
    }
    let address = WireSecretAddress::new(coordinates.item.clone(), coordinates.field.clone());
    address
        .validate()
        .map_err(|_| RpcError::new(ErrorKind::InvalidParams))?;
    Ok(coordinates)
}

pub(super) fn wire_address(address: Address) -> RpcResult<WireSecretAddress> {
    let coordinates = coordinates(address)?;
    Ok(WireSecretAddress::new(coordinates.item, coordinates.field))
}
