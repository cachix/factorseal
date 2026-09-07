use std::sync::atomic::{AtomicU64, Ordering};

use super::*;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum CopiedField {
    Draft(usize),
    Saved(usize),
}

fn passphrase_from_entropy(entropy: &[u8; 16]) -> Zeroizing<String> {
    let mnemonic =
        bip39::Mnemonic::from_entropy(entropy).expect("128 bits is a valid BIP-39 entropy length");
    Zeroizing::new(mnemonic.to_string())
}

fn generate_passphrase() -> Result<Zeroizing<String>, getrandom::Error> {
    let mut entropy = Zeroizing::new([0_u8; 16]);
    getrandom::fill(&mut *entropy)?;
    Ok(passphrase_from_entropy(&entropy))
}

pub(super) fn can_generate(kind: PersonalSecretKind, field: &PersonalDraftField) -> bool {
    field.field_type == PersonalFieldType::Concealed
        && (kind == PersonalSecretKind::Generic
            || field.id == "password"
            || field.id == "passphrase")
}

impl DesktopView {
    pub(super) fn generate_personal_password(
        &mut self,
        index: usize,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(field) = self.personal_fields.get(index) else {
            return;
        };
        if !can_generate(self.personal_kind, field) {
            return;
        }
        match generate_passphrase() {
            Ok(password) => {
                field
                    .value
                    .update(cx, |input, cx| input.set_value(&password, window, cx));
                self.personal_error = None;
                self.copied_personal_field = None;
            }
            Err(_) => {
                self.personal_error =
                    Some("Could not generate a passphrase. Please try again.".into());
            }
        }
        cx.notify();
    }

    pub(super) fn copy_personal_value(
        &mut self,
        value: String,
        field: CopiedField,
        cx: &mut Context<Self>,
    ) {
        static NEXT_COPY: AtomicU64 = AtomicU64::new(0);
        let marker = format!(
            "factorseal:{}:{}",
            std::process::id(),
            NEXT_COPY.fetch_add(1, Ordering::Relaxed)
        );
        cx.write_to_clipboard(gpui::ClipboardItem::new_string_with_metadata(
            value,
            marker.clone(),
        ));
        self.copied_personal_field = Some(field);
        cx.notify();
        cx.spawn(async move |view, cx| {
            smol::Timer::after(std::time::Duration::from_secs(2)).await;
            let _ = view.update(cx, |view, cx| {
                if view.copied_personal_field == Some(field) {
                    view.copied_personal_field = None;
                    cx.notify();
                }
            });
        })
        .detach();
        // Only clear our own clipboard entry; preserve anything copied afterwards.
        cx.spawn(async move |_, cx| {
            smol::Timer::after(std::time::Duration::from_secs(30)).await;
            cx.update(|cx| {
                if cx
                    .read_from_clipboard()
                    .as_ref()
                    .and_then(gpui::ClipboardItem::metadata)
                    == Some(&marker)
                {
                    cx.write_to_clipboard(gpui::ClipboardItem::new_string(String::new()));
                }
            });
        })
        .detach();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_passphrases_are_valid_twelve_word_bip39_mnemonics() {
        let first = generate_passphrase().unwrap();
        let second = generate_passphrase().unwrap();
        assert_ne!(*first, *second);
        for phrase in [first, second] {
            assert_eq!(phrase.split_whitespace().count(), 12);
            assert!(bip39::Mnemonic::parse_in(bip39::Language::English, &*phrase).is_ok());
        }
    }

    #[test]
    fn passphrases_match_the_bip39_zero_entropy_test_vector() {
        assert_eq!(
            &*passphrase_from_entropy(&[0; 16]),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
    }
}
