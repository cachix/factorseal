//! New-item forms based on 1Password CLI's built-in templates (2026-09-07).
//! <https://developer.1password.com/docs/cli/item-template-json/>
//! Kept separate from transfer templates so existing export mappings remain stable.
use super::{
    PersonalField, PersonalFieldType as T, PersonalSecret, PersonalSecretKind as K, PersonalSection,
};

type TemplateField = (&'static str, &'static str, T);
type TemplateSection<'a> = (&'static str, &'static str, &'a [TemplateField]);

#[allow(clippy::too_many_lines)]
pub(super) fn new_item_template(kind: K) -> PersonalSecret {
    if matches!(kind, K::Generic | K::Document) {
        return PersonalSecret::template(kind, String::new());
    }
    let sections: &[TemplateSection<'_>] = match kind {
        K::Login => &[
            (
                "account",
                "Login",
                &[
                    ("url-0", "Website", T::Url),
                    ("username", "Username", T::Text),
                    ("password", "Password", T::Concealed),
                    ("totp", "One-time password", T::Totp),
                ],
            ),
            ("notes", "Notes", &[("notes", "Notes", T::Multiline)]),
        ],
        K::SecureNote => &[("notes", "Notes", &[("notes", "Notes", T::Multiline)])],
        K::Card => &[
            (
                "card",
                "Card",
                &[
                    ("cardholderName", "Cardholder", T::Text),
                    ("type", "Type", T::Text),
                    ("number", "Card number", T::CardNumber),
                    ("code", "Security code", T::Concealed),
                    ("expiry", "Expiry date", T::MonthYear),
                    ("validFrom", "Valid from", T::MonthYear),
                ],
            ),
            (
                "contactInfo",
                "Contact Information",
                &[
                    ("bank", "Issuing bank", T::Text),
                    ("phoneLocal", "Phone (local)", T::Phone),
                    ("phoneTollFree", "Phone (toll free)", T::Phone),
                    ("phoneIntl", "Phone (intl)", T::Phone),
                    ("website", "Website", T::Url),
                ],
            ),
            (
                "details",
                "Additional Details",
                &[
                    ("pin", "PIN", T::Concealed),
                    ("creditLimit", "Credit limit", T::Text),
                    ("cashLimit", "Cash withdrawal limit", T::Text),
                    ("interest", "Interest rate", T::Text),
                    ("issuenumber", "Issue number", T::Text),
                ],
            ),
            ("notes", "Notes", &[("notes", "Notes", T::Multiline)]),
        ],
        K::Identity => &[
            (
                "name",
                "Identification",
                &[
                    ("firstName", "First name", T::Text),
                    ("initial", "Initial", T::Text),
                    ("lastName", "Last name", T::Text),
                    ("gender", "Gender", T::Text),
                    ("birthdate", "Birth date", T::Date),
                    ("occupation", "Occupation", T::Text),
                    ("company", "Company", T::Text),
                    ("department", "Department", T::Text),
                    ("jobtitle", "Job title", T::Text),
                ],
            ),
            (
                "address",
                "Address",
                &[
                    ("address", "Address", T::Address),
                    ("defphone", "Default phone", T::Phone),
                    ("homephone", "Home", T::Phone),
                    ("cellphone", "Cell", T::Phone),
                    ("busphone", "Business", T::Phone),
                ],
            ),
            (
                "internet",
                "Internet Details",
                &[
                    ("username", "Username", T::Text),
                    ("reminderq", "Reminder question", T::Text),
                    ("remindera", "Reminder answer", T::Text),
                    ("email", "Email", T::Email),
                    ("website", "Website", T::Text),
                    ("icq", "ICQ", T::Text),
                    ("skype", "Skype", T::Text),
                    ("aim", "AOL/AIM", T::Text),
                    ("yahoo", "Yahoo", T::Text),
                    ("msn", "MSN", T::Text),
                    ("forumsig", "Forum signature", T::Text),
                ],
            ),
            ("notes", "Notes", &[("notes", "Notes", T::Multiline)]),
        ],
        K::SshKey => &[
            (
                "ssh_key",
                "SSH key",
                &[("private-key", "Private key", T::SshKey)],
            ),
            ("notes", "Notes", &[("notes", "Notes", T::Multiline)]),
        ],
        K::ApiCredential => &[
            (
                "api_credential",
                "API credential",
                &[
                    ("username", "Username", T::Text),
                    ("credential", "Credential", T::Concealed),
                    ("type", "Type", T::Text),
                    ("filename", "Filename", T::Text),
                    ("validFrom", "Valid from", T::Date),
                    ("expires", "Expires", T::Date),
                    ("hostname", "Hostname", T::Text),
                ],
            ),
            ("notes", "Notes", &[("notes", "Notes", T::Multiline)]),
        ],
        K::Passport => &[
            (
                "passport",
                "Passport",
                &[
                    ("type", "Type", T::Text),
                    ("issuing_country", "Issuing country", T::Text),
                    ("number", "Number", T::Concealed),
                    ("fullname", "Full name", T::Text),
                    ("gender", "Gender", T::Text),
                    ("nationality", "Nationality", T::Text),
                    ("issuing_authority", "Issuing authority", T::Text),
                    ("birthdate", "Date of birth", T::Date),
                    ("birthplace", "Place of birth", T::Text),
                    ("issue_date", "Issued on", T::Date),
                    ("expiry_date", "Expiry date", T::Date),
                ],
            ),
            ("notes", "Notes", &[("notes", "Notes", T::Multiline)]),
        ],
        K::BankAccount => &[
            (
                "bank_account",
                "Bank account",
                &[
                    ("bankName", "Bank name", T::Text),
                    ("owner", "Name on account", T::Text),
                    ("accountType", "Type", T::Text),
                    ("routingNo", "Routing number", T::Text),
                    ("accountNo", "Account number", T::Concealed),
                    ("swift", "SWIFT", T::Text),
                    ("iban", "IBAN", T::Concealed),
                    ("telephonePin", "PIN", T::Concealed),
                ],
            ),
            (
                "branchInfo",
                "Branch Information",
                &[
                    ("branchPhone", "Phone", T::Phone),
                    ("branchAddress", "Address", T::Text),
                ],
            ),
            ("notes", "Notes", &[("notes", "Notes", T::Multiline)]),
        ],
        K::Generic | K::Document => unreachable!(),
    };
    let mut item = PersonalSecret::new(kind, String::new());
    item.sections = sections
        .iter()
        .map(|(id, label, fields)| PersonalSection {
            id: (*id).into(),
            label: (*label).into(),
            fields: fields
                .iter()
                .map(|(id, label, ty)| PersonalField::new(*id, *label, ty.clone(), ""))
                .collect(),
        })
        .collect();
    item
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_creation_template_round_trips() {
        for kind in K::ALL {
            let item = new_item_template(kind);
            assert!(!item.sections.is_empty());
            assert_eq!(
                item,
                PersonalSecret::decode_current(&item.encode().unwrap()).unwrap()
            );
            for section in &item.sections {
                for field in &section.fields {
                    assert_eq!(field.concealed, field.field_type.concealed());
                }
            }
        }
    }
}
