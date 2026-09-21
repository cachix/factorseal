use factorseal::{SecretSpecAddress, SecretSpecCoordinates};
use secretspec_ipc::error::{ErrorKind, RpcError};
use secretspec_ipc::protocol::provider::{Address, Coordinates};
use secretspec_ipc::server::RpcResult;

pub(super) fn coordinates(address: Address) -> Coordinates {
    match address {
        Address::Convention {
            project,
            profile,
            key,
        } => Coordinates {
            item: key,
            field: None,
            vault: Some(project),
            section: Some(profile),
            version: None,
        },
        Address::Native { coordinates } => coordinates,
    }
}

pub(super) fn wire_address(address: Address) -> RpcResult<SecretSpecAddress> {
    let address = match address {
        Address::Convention {
            project,
            profile,
            key,
        } => SecretSpecAddress::convention(project, profile, key),
        Address::Native { coordinates } => SecretSpecAddress::native(SecretSpecCoordinates {
            item: coordinates.item,
            field: coordinates.field,
            vault: coordinates.vault,
            section: coordinates.section,
            version: coordinates.version,
        }),
    };
    address.map_err(|_| RpcError::new(ErrorKind::InvalidParams))
}
