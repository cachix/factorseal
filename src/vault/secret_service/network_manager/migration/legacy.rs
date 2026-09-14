//! Read the NM schema used by libsecret clients. Never enumerate unrelated
//! credentials, unlock a collection implicitly, or delete an unverified item.

use super::{
    BTreeMap, Connection, OwnedObjectPath, OwnedValue, Property, Value, WireSecret, fdo, proxy,
};
use std::collections::HashMap;
use zeroize::Zeroizing;

pub(crate) struct Legacy {
    connection: Connection,
    owner: String,
    session: OwnedObjectPath,
}

fn attributes(uuid: &str, property: Property) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("connection-uuid".into(), uuid.into()),
        ("setting-name".into(), property.setting().into()),
        ("setting-key".into(), property.name().into()),
    ])
}

impl Legacy {
    pub(super) async fn connect() -> zbus::Result<Self> {
        let connection = Connection::session().await?;
        let bus = fdo::DBusProxy::new(&connection).await?;
        let owner = bus
            .get_name_owner("org.freedesktop.secrets".try_into()?)
            .await?
            .to_string();
        drop(bus);
        Self::connect_on(connection, owner).await
    }

    pub(super) async fn connect_on(connection: Connection, owner: String) -> zbus::Result<Self> {
        let service = proxy(
            &connection,
            &owner,
            "/org/freedesktop/secrets",
            "org.freedesktop.Secret.Service",
        )
        .await?;
        let (_, session): (OwnedValue, OwnedObjectPath) = service
            .call("OpenSession", &("plain", Value::from("")))
            .await?;
        drop(service);
        Ok(Self {
            connection,
            owner,
            session,
        })
    }

    pub(super) async fn close(self) {
        if let Ok(session) = proxy(
            &self.connection,
            &self.owner,
            self.session.as_str(),
            "org.freedesktop.Secret.Session",
        )
        .await
        {
            let _ = session.call::<_, _, ()>("Close", &()).await;
        }
    }

    pub(super) async fn find(
        &self,
        uuid: &str,
        property: Property,
    ) -> Result<Vec<(OwnedObjectPath, WireSecret)>, &'static str> {
        let service = proxy(
            &self.connection,
            &self.owner,
            "/org/freedesktop/secrets",
            "org.freedesktop.Secret.Service",
        )
        .await
        .map_err(|_| "Previous keyring is unavailable")?;
        let (unlocked, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = service
            .call("SearchItems", &(attributes(uuid, property),))
            .await
            .map_err(|_| "Cannot search the previous keyring")?;
        if !locked.is_empty() {
            return Err("Unlock the previous keyring and retry");
        }
        if unlocked.len() > 16 {
            return Err("Too many matching keyring entries; resolve duplicates first");
        }
        let mut values = Vec::new();
        for path in unlocked {
            let value = self.read_verified(&path, uuid, property).await?;
            values.push((path, value));
        }
        Ok(values)
    }

    async fn read_verified(
        &self,
        path: &OwnedObjectPath,
        uuid: &str,
        property: Property,
    ) -> Result<WireSecret, &'static str> {
        let item = proxy(
            &self.connection,
            &self.owner,
            path.as_str(),
            "org.freedesktop.Secret.Item",
        )
        .await
        .map_err(|_| "Previous keyring item disappeared")?;
        let actual: HashMap<String, String> = item
            .get_property("Attributes")
            .await
            .map_err(|_| "Cannot verify keyring item identity")?;
        if attributes(uuid, property)
            .iter()
            .any(|(key, value)| actual.get(key) != Some(value))
        {
            return Err("Previous keyring item identity changed");
        }
        let (session, parameters, bytes, _): crate::vault::secret_service::Secret = item
            .call("GetSecret", &(&self.session,))
            .await
            .map_err(|_| "Cannot read the previous keyring; unlock it and retry")?;
        let bytes = Zeroizing::new(bytes);
        if session != self.session || !parameters.is_empty() {
            return Err("Invalid keyring session reply");
        }
        WireSecret::new(bytes.to_vec()).map_err(|_| "Cannot protect the keyring credential")
    }

    pub(super) async fn delete_verified(
        &self,
        path: &OwnedObjectPath,
        uuid: &str,
        property: Property,
        value: &WireSecret,
    ) -> Result<(), &'static str> {
        if self.read_verified(path, uuid, property).await?.expose() != value.expose() {
            return Err("Previous keyring value changed; retained the old copy");
        }
        let item = proxy(
            &self.connection,
            &self.owner,
            path.as_str(),
            "org.freedesktop.Secret.Item",
        )
        .await
        .map_err(|_| "Cannot reach the old keyring item for cleanup")?;
        let prompt: OwnedObjectPath = item
            .call("Delete", &())
            .await
            .map_err(|_| "Credentials moved, but previous keyring cleanup failed")?;
        if prompt.as_str() != "/" {
            return Err(
                "Credentials moved; previous keyring requires confirmation before deleting its copy",
            );
        }
        Ok(())
    }
}
