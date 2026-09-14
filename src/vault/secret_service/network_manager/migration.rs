//! Copy and verify before changing NM's persistent profile. Failed or ambiguous
//! updates retain the vault copy; we never roll back by deleting the only copy.

use super::{
    Arc, BTreeMap, Connection, Duration, Ordering, OwnedObjectPath, OwnedValue, PROPERTIES,
    Profile, Settings, Shared, Store, Value, VaultMutation, WireSecret, fdo, mutate, name_mutation,
    profile::Property, protocol, read, string_variant,
};
use crate::vault::{VaultError, VaultResult};
use protocol::SecretFlags;

mod legacy;
use legacy::Legacy;

#[cfg(all(test, feature = "vault"))]
mod tests;

const CONNECTION: &str = "org.freedesktop.NetworkManager.Settings.Connection";

/// Per-connection migration result, containing no secret values.
#[derive(Clone, Debug)]
pub struct WifiMigrationEntry {
    pub connection: String,
    pub migrated: bool,
    pub message: String,
}

/// Results for the Wi-Fi profiles visible to the current user.
#[derive(Clone, Debug, Default)]
pub struct WifiMigrationReport {
    pub entries: Vec<WifiMigrationEntry>,
}

struct Guard {
    shared: Arc<Shared>,
    uuid: String,
}

impl Guard {
    fn acquire(shared: &Arc<Shared>, uuid: &str) -> Result<Self, &'static str> {
        let mut migrations = shared
            .wifi_migrations
            .lock()
            .map_err(|_| "Migration state unavailable")?;
        if migrations.get(uuid).is_some_and(|(_, active)| *active) {
            return Err("Migration is already running");
        }
        let generation = if uuid == "migration-batch" {
            0
        } else {
            shared.wifi_generation.fetch_add(1, Ordering::SeqCst) + 1
        };
        migrations.insert(uuid.into(), (generation, true));
        Ok(Self {
            shared: Arc::clone(shared),
            uuid: uuid.into(),
        })
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let Ok(mut migrations) = self.shared.wifi_migrations.lock()
            && let Some((_, active)) = migrations.get_mut(&self.uuid)
        {
            *active = false;
        }
    }
}

pub(in crate::vault::secret_service) async fn run(
    shared: Arc<Shared>,
) -> VaultResult<WifiMigrationReport> {
    let _batch = Guard::acquire(&shared, "migration-batch")
        .map_err(|message| VaultError::Protocol(message.into()))?;
    shared.agent().map_err(|_| {
        VaultError::Protocol("Unlock FactorSeal before moving Wi-Fi passwords".into())
    })?;
    let connection = Connection::system()
        .await
        .map_err(|_| VaultError::Protocol("Cannot reach the system bus".into()))?;
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        let bus = fdo::DBusProxy::new(&connection).await?;
        let owner = bus.get_name_owner(protocol::BUS_NAME.try_into()?).await?;
        let settings = proxy(
            &connection,
            owner.as_str(),
            "/org/freedesktop/NetworkManager/Settings",
            "org.freedesktop.NetworkManager.Settings",
        )
        .await?;
        let paths: Vec<OwnedObjectPath> = settings.call("ListConnections", &()).await?;
        Ok::<_, zbus::Error>((owner.to_string(), paths))
    })
    .await;
    let (owner, paths) = result
        .ok()
        .and_then(Result::ok)
        .ok_or_else(|| VaultError::Protocol("Cannot list NetworkManager connections".into()))?;
    if paths.len() > 1024 {
        return Err(VaultError::Protocol(
            "Too many NetworkManager connections".into(),
        ));
    }
    let legacy = tokio::time::timeout(Duration::from_secs(10), Legacy::connect())
        .await
        .ok()
        .and_then(Result::ok);
    let mut report = WifiMigrationReport::default();
    for path in paths {
        if shared.locked() {
            break;
        }
        let result = tokio::time::timeout(Duration::from_secs(90), async {
            let connection_proxy = proxy(&connection, &owner, path.as_str(), CONNECTION).await
                .map_err(|_| "Cannot reach this connection")?;
            migrate_connection(&connection_proxy, &shared, legacy.as_ref()).await
        }).await.unwrap_or(Err("Timed out; any verified vault copies have been retained. Retry after checking permissions"));
        match result {
            Ok(Some(entry)) => report.entries.push(entry),
            Ok(None) => {}
            Err(message) => report.entries.push(WifiMigrationEntry {
                connection: path.to_string(),
                migrated: false,
                message: message.into(),
            }),
        }
    }
    if shared.locked() {
        report.entries.push(WifiMigrationEntry {
            connection: "Remaining connections".into(),
            migrated: false,
            message: "Vault sealed; unlock and retry. Verified copies have been retained".into(),
        });
    }
    if let Some(legacy) = legacy {
        legacy.close().await;
    }
    Ok(report)
}

async fn proxy<'a>(
    connection: &'a Connection,
    owner: &'a str,
    path: &'a str,
    interface: &'a str,
) -> zbus::Result<zbus::Proxy<'a>> {
    zbus::proxy::Builder::new(connection)
        .destination(owner)?
        .path(path)?
        .interface(interface)?
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await
}

struct Copy {
    property: Property,
    value: WireSecret,
    legacy_paths: Vec<OwnedObjectPath>,
}

/// A nonzero VersionId is required. Do not silently fall back to an unchecked
/// read-modify-write on older NetworkManager releases.
pub(super) async fn migrate_connection(
    connection: &zbus::Proxy<'_>,
    shared: &Arc<Shared>,
    legacy: Option<&Legacy>,
) -> Result<Option<WifiMigrationEntry>, &'static str> {
    let version: u64 = connection
        .get_property("VersionId")
        .await
        .map_err(|_| "Migration needs NetworkManager 1.44 or newer (VersionId unavailable)")?;
    if version == 0 {
        return Err("Cannot safely update an unversioned profile");
    }
    let settings: Settings = connection
        .call("GetSettings", &())
        .await
        .map_err(|_| "Cannot read profile settings")?;
    if settings
        .get("connection")
        .and_then(|s| s.get("type"))
        .and_then(|v| <&str>::try_from(v).ok())
        != Some("802-11-wireless")
    {
        return Ok(None);
    }
    let label = settings
        .get("connection")
        .and_then(|s| s.get("id"))
        .and_then(|v| <&str>::try_from(v).ok())
        .unwrap_or("Wi-Fi connection")
        .to_owned();
    let result = migrate_profile(connection, shared, legacy, version, settings).await;
    Ok(Some(WifiMigrationEntry {
        connection: label,
        migrated: result.is_ok(),
        message: result.unwrap_or_else(|message| {
            format!(
                "Not completed: {message}. Any verified vault copy is retained; retry when resolved"
            )
        }),
    }))
}

async fn collect(
    store: &Store,
    profile: &Profile,
    legacy: Option<&Legacy>,
) -> Result<Vec<Copy>, &'static str> {
    let mut copies = Vec::new();
    for credential in &profile.credentials {
        if credential
            .flags
            .intersects(SecretFlags::NOT_SAVED | SecretFlags::NOT_REQUIRED)
            || credential.flags.bits() & !SecretFlags::all().bits() != 0
        {
            continue;
        }
        let property = credential.property;
        let old = if let Some(legacy) = legacy {
            legacy.find(&profile.uuid, property).await?
        } else {
            Vec::new()
        };
        let stored = read(store.clone(), property.address(&profile.uuid))
            .await
            .map_err(|_| "Cannot read the vault")?;
        let source = credential
            .supplied
            .as_ref()
            .or_else(|| old.first().map(|(_, value)| value))
            .or_else(|| {
                credential
                    .flags
                    .agent_may_save()
                    .then_some(stored.as_ref())
                    .flatten()
            });
        let Some(source) = source else {
            if credential.needed {
                return Err(
                    "A required password is unavailable; unlock the previous keyring or enter it in the connection editor",
                );
            }
            continue;
        };
        property
            .validate(&profile.key_management, source.expose())
            .map_err(|_| "An existing credential has an unsupported value")?;
        if stored
            .as_ref()
            .is_some_and(|stored| stored.expose() != source.expose())
        {
            return Err(
                "The vault already contains a different credential; resolve the conflict first",
            );
        }
        if old
            .iter()
            .any(|(_, value)| value.expose() != source.expose())
        {
            return Err(
                "The previous keyring contains a different credential; resolve the conflict first",
            );
        }
        copies.push(Copy {
            property,
            value: WireSecret::new(source.expose().to_vec())
                .map_err(|_| "Cannot protect the credential in memory")?,
            legacy_paths: old.into_iter().map(|(path, _)| path).collect(),
        });
    }
    Ok(copies)
}

fn ensure_unlocked(
    shared: &Shared,
    agent: &Arc<super::super::agent::Agent>,
) -> Result<(), &'static str> {
    if shared
        .agent()
        .is_ok_and(|current| Arc::ptr_eq(&current, agent))
    {
        Ok(())
    } else {
        Err("Vault changed or sealed during migration")
    }
}

async fn verify(store: &Store, profile: &Profile, copies: &[Copy]) -> Result<(), &'static str> {
    for copy in copies {
        if read(store.clone(), copy.property.address(&profile.uuid))
            .await
            .map_err(|_| "Cannot verify the vault copy")?
            .is_none_or(|stored| stored.expose() != copy.value.expose())
        {
            return Err(
                "Vault verification failed; profile and old keyring have not been cleaned up",
            );
        }
    }
    Ok(())
}

async fn read_credentials(
    connection: &zbus::Proxy<'_>,
    mut settings: Settings,
) -> Result<(Profile, Settings), &'static str> {
    let profile = Profile::parse(&settings, &[]).map_err(|_| "Unsupported Wi-Fi profile")?;
    if connection
        .get_property::<bool>("Unsaved")
        .await
        .map_err(|_| "Cannot check profile persistence")?
    {
        return Err("Save pending connection edits before migrating");
    }
    // GetSecrets never prompts for a new password. NM enforces the caller's
    // authorization and may return system storage or the current agent's values.
    let secrets: Settings = match connection.call("GetSecrets", &(profile.setting,)).await {
        Ok(secrets) => secrets,
        Err(zbus::Error::MethodError(name, _, _)) if name.as_str().ends_with(".NoSecrets") => {
            Settings::new()
        }
        Err(_) => return Err("Cannot read NetworkManager secrets; check authorization and retry"),
    };
    if let Some(values) = secrets
        .into_iter()
        .find_map(|(setting, values)| (setting == profile.setting).then_some(values))
    {
        let target = settings
            .get_mut(profile.setting)
            .ok_or("Missing security settings")?;
        for (key, value) in values {
            // Merge values only. NM's returned flags/metadata must not replace
            // the versioned GetSettings snapshot used to decide persistence.
            if PROPERTIES
                .iter()
                .any(|property| property.setting() == profile.setting && property.name() == key)
            {
                target.insert(key, value);
            } else if key != "name" {
                return Err("The profile contains an unsupported secret property");
            }
        }
    }
    let profile = Profile::parse(&settings, &[]).map_err(|_| "Invalid stored credentials")?;
    Ok((profile, settings))
}

async fn migrate_profile(
    connection: &zbus::Proxy<'_>,
    shared: &Arc<Shared>,
    legacy: Option<&Legacy>,
    version: u64,
    settings: Settings,
) -> Result<String, &'static str> {
    let agent = shared.agent().map_err(|_| "Unlock the vault first")?;
    let _write = shared.wifi_writes.lock().await;
    let uuid = Profile::uuid(&settings).map_err(|_| "Unsupported Wi-Fi profile")?;
    let _guard = Guard::acquire(shared, &uuid)?;
    let (profile, mut settings) = read_credentials(connection, settings).await?;
    let copies = collect(&agent.store, &profile, legacy).await?;
    if copies.is_empty() {
        return Ok(
            "No saved credentials to move; temporary credentials were left unchanged".into(),
        );
    }
    ensure_unlocked(shared, &agent)?;
    let mut writes = Vec::new();
    for copy in &copies {
        writes.push(VaultMutation::Put {
            address: copy.property.address(&profile.uuid),
            value: WireSecret::new(copy.value.expose().to_vec())
                .map_err(|_| "Cannot protect the credential")?,
            evict_at: None,
        });
    }
    writes.push(name_mutation(&profile).map_err(|_| "Invalid connection name")?);
    mutate(agent.store.clone(), writes)
        .await
        .map_err(|_| "Cannot save credentials in the vault")?;
    verify(&agent.store, &profile, &copies).await?;
    ensure_unlocked(shared, &agent)?;
    let values = settings
        .get_mut(profile.setting)
        .ok_or("Missing security settings")?;
    for copy in &copies {
        values.insert(
            copy.property.flags_name().into(),
            OwnedValue::from(SecretFlags::AGENT_OWNED.bits()),
        );
        let value = if copy.property.is_raw() {
            OwnedValue::try_from(Value::from(copy.value.expose().to_vec()))
                .map_err(|_| "Invalid binary credential")?
        } else {
            string_variant(
                std::str::from_utf8(copy.value.expose()).map_err(|_| "Invalid text credential")?,
            )
        };
        values.insert(copy.property.name().into(), value);
    }
    // NM's settings plugin omits agent-owned values from persistent profiles.
    // Include them in the update so the daemon does not lose other secret state.
    let args = BTreeMap::from([("version-id", OwnedValue::from(version))]);
    let _: BTreeMap<String, OwnedValue> = connection
        .call("Update2", &(settings, 0x41_u32, args))
        .await
        .map_err(
            |_| "Profile update failed or was rejected; check authorization and concurrent edits",
        )?;
    let updated: Settings = connection
        .call("GetSettings", &())
        .await
        .map_err(|_| "Cannot verify the updated profile")?;
    if Profile::uuid(&updated).map_err(|_| "Profile identity changed")? != profile.uuid {
        return Err("Profile identity changed");
    }
    for copy in &copies {
        let flag = updated
            .get(profile.setting)
            .and_then(|values| values.get(copy.property.flags_name()))
            .and_then(|v| u32::try_from(v).ok());
        if flag != Some(SecretFlags::AGENT_OWNED.bits()) {
            return Err("Updated profile did not retain agent-owned storage");
        }
    }
    verify(&agent.store, &profile, &copies).await?;
    ensure_unlocked(shared, &agent)?;
    if let Some(legacy) = legacy {
        for copy in &copies {
            for path in &copy.legacy_paths {
                ensure_unlocked(shared, &agent)?;
                legacy
                    .delete_verified(path, &profile.uuid, copy.property, &copy.value)
                    .await?;
            }
        }
        Ok(format!("Moved and verified {} credential(s)", copies.len()))
    } else {
        Ok(format!(
            "Moved and verified {} credential(s). Previous keyring unavailable; old keyring copies were not checked",
            copies.len()
        ))
    }
}
