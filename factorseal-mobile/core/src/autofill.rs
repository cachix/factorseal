use crate::api::{ErrorCode, Login, Site};
use crate::core::{Failure, Outcome};
use factorseal::personal::{PersonalField, PersonalFieldType, PersonalSecret, website};

const APP_SCHEME: &str = "androidapp://";
const MAX_PACKAGE: usize = 255;

pub(crate) enum Target {
    Origin(String),
    App(String),
}

impl Target {
    pub(crate) fn of(site: &Site) -> Outcome<Self> {
        match site {
            Site::Web(address) => website::origin(address).map(Self::Origin).ok_or_else(|| {
                Failure::new(
                    ErrorCode::Invalid,
                    "autofill only fills websites that use https",
                )
            }),
            Site::App(package) if is_package(package) => {
                Ok(Self::App(format!("{APP_SCHEME}{package}")))
            }
            Site::App(_) => Err(Failure::new(
                ErrorCode::Invalid,
                "the app name is not valid",
            )),
        }
    }

    pub(crate) fn links(&self, item: &PersonalSecret) -> bool {
        match self {
            Self::Origin(origin) => item.is_login_for(origin),
            Self::App(address) => {
                item.is_fillable_login() && websites(item).any(|website| website.trim() == address)
            }
        }
    }

    pub(crate) const fn learns(&self) -> bool {
        matches!(self, Self::App(_))
    }

    fn address(&self) -> &str {
        match self {
            Self::Origin(address) | Self::App(address) => address,
        }
    }
}

pub(crate) fn login(item: &PersonalSecret) -> Login {
    Login {
        id: item.id.clone(),
        title: item.title.clone(),
        username: item.username().unwrap_or_default().to_owned(),
    }
}

pub(crate) fn link(item: &mut PersonalSecret, target: &Target) {
    let ids: Vec<String> = fields(item).map(|field| field.id.clone()).collect();
    let id = (0..=ids.len())
        .map(|number| format!("url-{number}"))
        .find(|id| !ids.contains(id))
        .unwrap_or_default();
    let field = PersonalField::new(
        id,
        PersonalFieldType::Url.label(),
        PersonalFieldType::Url,
        target.address(),
    );
    let home = item
        .sections
        .iter()
        .rposition(|section| {
            section
                .fields
                .iter()
                .any(|field| field.field_type == PersonalFieldType::Url)
        })
        .or_else(|| {
            item.sections
                .iter()
                .position(|section| section.fields.iter().any(|field| field.id == "username"))
        })
        .unwrap_or_default();
    if let Some(section) = item.sections.get_mut(home) {
        let at = section
            .fields
            .iter()
            .rposition(|field| field.field_type == PersonalFieldType::Url)
            .map_or(section.fields.len(), |index| index + 1);
        section.fields.insert(at, field);
    }
}

pub(crate) fn new_login(
    target: &Target,
    title: &str,
    username: &str,
    password: &str,
) -> PersonalSecret {
    let title = match title.trim() {
        "" => target.address(),
        title => title,
    };
    let mut item = PersonalSecret::login(title.to_owned(), target.address(), username);
    item.set_password(password);
    item
}

fn fields(item: &PersonalSecret) -> impl Iterator<Item = &PersonalField> {
    item.sections.iter().flat_map(|section| &section.fields)
}

fn websites(item: &PersonalSecret) -> impl Iterator<Item = &str> {
    fields(item)
        .filter(|field| field.field_type == PersonalFieldType::Url)
        .filter_map(PersonalField::text)
}

fn is_package(name: &str) -> bool {
    name.len() <= MAX_PACKAGE
        && name.split('.').count() >= 2
        && name.split('.').all(|segment| {
            segment
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphabetic())
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
}
