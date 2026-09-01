//! Versioned unlock policy shared by native and embedded vaults.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::vault::{VaultError, VaultResult};

const UNLOCK_POLICY_VERSION: u32 = 1;
const MAX_UNLOCK_GROUPS: usize = 8;

/// One user-controlled requirement in an unlock group.
///
/// Platform hardware binding is implicit in every group and is therefore not
/// represented as a removable factor here.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum UnlockFactorKind {
    /// A PBKDF2-HMAC-SHA-256-stretched Factorseal password.
    Password,
    /// Platform biometric approval gates use of the hardware wrapping key.
    Biometric,
}

impl UnlockFactorKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Biometric => "biometric",
        }
    }
}

impl std::fmt::Display for UnlockFactorKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for UnlockFactorKind {
    type Err = VaultError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "password" => Ok(Self::Password),
            "biometric" => Ok(Self::Biometric),
            _ => Err(VaultError::Protection(format!(
                "unknown unlock factor `{value}`; expected password or biometric"
            ))),
        }
    }
}

/// Factors inside one group are all required (logical AND).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnlockGroup {
    factors: Vec<UnlockFactorKind>,
}

impl UnlockGroup {
    /// Construct a canonical unlock group, rejecting empty or repeated factors.
    pub fn new(factors: impl IntoIterator<Item = UnlockFactorKind>) -> VaultResult<Self> {
        let supplied: Vec<_> = factors.into_iter().collect();
        let canonical: BTreeSet<_> = supplied.iter().copied().collect();
        if canonical.is_empty() {
            return Err(VaultError::Protection(
                "an unlock group must contain at least one factor".to_owned(),
            ));
        }
        if canonical.len() != supplied.len() {
            return Err(VaultError::Protection(
                "an unlock group contains a repeated factor".to_owned(),
            ));
        }
        Ok(Self {
            factors: canonical.into_iter().collect(),
        })
    }

    /// Factors that must all be satisfied for this group.
    #[must_use]
    pub fn factors(&self) -> &[UnlockFactorKind] {
        &self.factors
    }

    #[must_use]
    pub fn requires(&self, factor: UnlockFactorKind) -> bool {
        self.factors.binary_search(&factor).is_ok()
    }

    pub(super) fn validate(&self) -> VaultResult<()> {
        Self::new(self.factors.iter().copied()).map(|_| ())
    }
}

impl std::fmt::Display for UnlockGroup {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, factor) in self.factors.iter().enumerate() {
            if index != 0 {
                formatter.write_str(",")?;
            }
            factor.fmt(formatter)?;
        }
        Ok(())
    }
}

impl std::str::FromStr for UnlockGroup {
    type Err = VaultError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(
            value
                .split(',')
                .map(str::trim)
                .map(str::parse)
                .collect::<VaultResult<Vec<_>>>()?,
        )
    }
}

/// Alternative unlock groups. Satisfying any one group unlocks the vault.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnlockPolicy {
    version: u32,
    groups: Vec<UnlockGroup>,
}

impl UnlockPolicy {
    /// Construct a policy where each group is an OR alternative.
    pub fn new(groups: impl IntoIterator<Item = UnlockGroup>) -> VaultResult<Self> {
        let groups: Vec<_> = groups.into_iter().collect();
        let policy = Self {
            version: UNLOCK_POLICY_VERSION,
            groups,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// OR alternatives in this policy.
    #[must_use]
    pub fn groups(&self) -> &[UnlockGroup] {
        &self.groups
    }

    pub(super) fn validate(&self) -> VaultResult<()> {
        if self.version != UNLOCK_POLICY_VERSION
            || self.groups.is_empty()
            || self.groups.len() > MAX_UNLOCK_GROUPS
        {
            return Err(VaultError::Protection(
                "unsupported or invalid unlock policy".to_owned(),
            ));
        }
        for group in &self.groups {
            group.validate()?;
        }
        for (index, group) in self.groups.iter().enumerate() {
            if self.groups[..index].contains(group) {
                return Err(VaultError::Protection(
                    "unlock policy contains a repeated group".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Secret inputs available while creating or satisfying an unlock group.
#[derive(Clone, Copy, Default)]
pub struct UnlockCredentials<'a> {
    password: Option<&'a [u8]>,
}

impl<'a> UnlockCredentials<'a> {
    #[must_use]
    pub const fn none() -> Self {
        Self { password: None }
    }

    #[must_use]
    pub const fn with_password(password: &'a [u8]) -> Self {
        Self {
            password: Some(password),
        }
    }

    #[cfg(feature = "key-protection")]
    pub(super) fn password_for(self, group: &UnlockGroup) -> VaultResult<Option<&'a [u8]>> {
        if !group.requires(UnlockFactorKind::Password) {
            return Ok(None);
        }
        let password = self.password.ok_or_else(|| {
            VaultError::Protection(format!("the {group} unlock group requires a password"))
        })?;
        if password.is_empty() {
            return Err(VaultError::Protection(
                "the password factor must not be empty".to_owned(),
            ));
        }
        Ok(Some(password))
    }
}

impl std::fmt::Debug for UnlockCredentials<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UnlockCredentials")
            .field("password", &self.password.map(|_| "[REDACTED]"))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_are_and_and_repeated_groups_are_or() {
        let both =
            UnlockGroup::new([UnlockFactorKind::Biometric, UnlockFactorKind::Password]).unwrap();
        assert_eq!(both.to_string(), "password,biometric");
        let recovery = UnlockGroup::new([UnlockFactorKind::Password]).unwrap();
        let policy = UnlockPolicy::new([both.clone(), recovery]).unwrap();
        assert_eq!(policy.groups()[0], both);
    }

    #[test]
    fn empty_and_repeated_policy_terms_are_rejected() {
        assert!(UnlockGroup::new([]).is_err());
        assert!(
            UnlockGroup::new([UnlockFactorKind::Password, UnlockFactorKind::Password]).is_err()
        );
        let password = UnlockGroup::new([UnlockFactorKind::Password]).unwrap();
        assert!(UnlockPolicy::new([password.clone(), password]).is_err());
    }
}
