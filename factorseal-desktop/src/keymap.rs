use std::collections::BTreeMap;

use gpui::Keystroke;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum Shortcut {
    OpenPalette,
    FocusSearch,
    NewLogin,
    EditItem,
    SaveItem,
    CopyPassword,
    CopyUsername,
    PasteQrCode,
    Undo,
    Redo,
    SealVault,
    OpenSettings,
    ShowShortcuts,
}

impl Shortcut {
    pub(crate) const ALL: [Self; 13] = [
        Self::OpenPalette,
        Self::FocusSearch,
        Self::NewLogin,
        Self::EditItem,
        Self::SaveItem,
        Self::CopyPassword,
        Self::CopyUsername,
        Self::PasteQrCode,
        Self::Undo,
        Self::Redo,
        Self::SealVault,
        Self::OpenSettings,
        Self::ShowShortcuts,
    ];

    pub(crate) const fn id(self) -> &'static str {
        match self {
            Self::OpenPalette => "open-palette",
            Self::FocusSearch => "focus-search",
            Self::NewLogin => "new-login",
            Self::EditItem => "edit-item",
            Self::SaveItem => "save-item",
            Self::CopyPassword => "copy-password",
            Self::CopyUsername => "copy-username",
            Self::PasteQrCode => "paste-qr-code",
            Self::Undo => "undo",
            Self::Redo => "redo",
            Self::SealVault => "seal-vault",
            Self::OpenSettings => "open-settings",
            Self::ShowShortcuts => "show-shortcuts",
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::OpenPalette => "Search items and actions",
            Self::FocusSearch => "Search the vault",
            Self::NewLogin => "New login",
            Self::EditItem => "Edit item",
            Self::SaveItem => "Save changes",
            Self::CopyPassword => "Copy password",
            Self::CopyUsername => "Copy username",
            Self::PasteQrCode => "Paste a QR code",
            Self::Undo => "Undo",
            Self::Redo => "Redo",
            Self::SealVault => "Seal now",
            Self::OpenSettings => "Settings",
            Self::ShowShortcuts => "Keyboard shortcuts",
        }
    }

    pub(crate) const fn defaults(self) -> &'static [&'static str] {
        match self {
            Self::OpenPalette => &["secondary-k", "secondary-shift-p"],
            Self::FocusSearch => &["secondary-f"],
            Self::NewLogin => &["secondary-n"],
            Self::EditItem => &["secondary-e"],
            Self::SaveItem => &["secondary-s"],
            Self::CopyPassword => &["secondary-c"],
            Self::CopyUsername => &["secondary-shift-c"],
            Self::PasteQrCode => &["secondary-v"],
            Self::Undo => &["secondary-z"],
            Self::Redo => &["secondary-shift-z"],
            Self::SealVault => &["secondary-l"],
            Self::OpenSettings => &["secondary-,"],
            Self::ShowShortcuts => &["secondary-/"],
        }
    }

    pub(crate) fn keys(self, overrides: &BTreeMap<String, String>) -> Vec<Keystroke> {
        match overrides.get(self.id()) {
            Some(keys) => parse(keys).into_iter().collect(),
            None => self
                .defaults()
                .iter()
                .filter_map(|keys| parse(keys))
                .collect(),
        }
    }

    pub(crate) fn changed(self, overrides: &BTreeMap<String, String>) -> bool {
        overrides.contains_key(self.id())
    }
}

pub(crate) fn parse(keys: &str) -> Option<Keystroke> {
    Keystroke::parse(keys)
        .ok()
        .filter(|keystroke| !keystroke.key.is_empty())
}

pub(crate) fn usable(keystroke: &Keystroke) -> bool {
    let modifiers = keystroke.modifiers;
    let function = keystroke
        .key
        .strip_prefix('f')
        .is_some_and(|number| number.parse::<u8>().is_ok_and(|number| number > 0));
    !matches!(
        keystroke.key.as_str(),
        "shift" | "control" | "alt" | "platform" | "function"
    ) && (modifiers.control
        || modifiers.alt
        || (modifiers.platform && cfg!(target_os = "macos"))
        || function)
}

pub(crate) fn same(left: &Keystroke, right: &Keystroke) -> bool {
    left.modifiers == right.modifiers && left.key == right.key
}

pub(crate) fn clash(
    shortcut: Shortcut,
    keystroke: &Keystroke,
    overrides: &BTreeMap<String, String>,
) -> Option<Shortcut> {
    Shortcut::ALL.into_iter().find(|other| {
        *other != shortcut
            && other
                .keys(overrides)
                .iter()
                .any(|keys| same(keys, keystroke))
    })
}

const TEXT_EDITING: [&str; 11] = [
    "secondary-a",
    "secondary-c",
    "secondary-v",
    "secondary-x",
    "secondary-z",
    "secondary-shift-z",
    "secondary-y",
    "secondary-backspace",
    "secondary-delete",
    "secondary-left",
    "secondary-right",
];

impl Shortcut {
    pub(crate) const fn works_in_text_fields(self) -> bool {
        matches!(self, Self::FocusSearch)
    }
}

pub(crate) fn edits_text(keystroke: &Keystroke) -> bool {
    TEXT_EDITING
        .iter()
        .filter_map(|keys| parse(keys))
        .any(|keys| same(&keys, keystroke))
}

pub(crate) fn reset_clash(
    shortcut: Shortcut,
    overrides: &BTreeMap<String, String>,
) -> Option<(Keystroke, Shortcut)> {
    let mut reset = overrides.clone();
    reset.remove(shortcut.id());
    shortcut
        .keys(&reset)
        .into_iter()
        .find_map(|keystroke| clash(shortcut, &keystroke, &reset).map(|other| (keystroke, other)))
}

pub(crate) fn valid(overrides: &BTreeMap<String, String>) -> bool {
    overrides
        .values()
        .all(|keys| keys.is_empty() || parse(keys).is_some_and(|keystroke| usable(&keystroke)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn overrides(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(id, keys)| ((*id).to_owned(), (*keys).to_owned()))
            .collect()
    }

    #[test]
    fn every_default_parses_and_needs_a_modifier() {
        for shortcut in Shortcut::ALL {
            assert_eq!(
                shortcut.keys(&BTreeMap::new()).len(),
                shortcut.defaults().len(),
                "{shortcut:?}"
            );
            for keystroke in shortcut.keys(&BTreeMap::new()) {
                assert!(usable(&keystroke), "{shortcut:?}");
            }
        }
    }

    #[test]
    fn defaults_never_clash() {
        for shortcut in Shortcut::ALL {
            for keystroke in shortcut.keys(&BTreeMap::new()) {
                assert_eq!(clash(shortcut, &keystroke, &BTreeMap::new()), None);
            }
        }
    }

    #[test]
    fn a_changed_shortcut_replaces_every_default() {
        let changed = overrides(&[("open-palette", "alt-p"), ("seal-vault", "")]);
        let palette = Shortcut::OpenPalette.keys(&changed);
        assert_eq!(palette.len(), 1);
        assert!(same(&palette[0], &parse("alt-p").unwrap()));
        assert_eq!(Shortcut::SealVault.keys(&changed).len(), 0);
        assert!(Shortcut::SealVault.changed(&changed));
        assert!(!Shortcut::Undo.changed(&changed));
    }

    #[test]
    fn clashes_name_the_other_shortcut() {
        let copy = parse("secondary-c").unwrap();
        assert_eq!(
            clash(Shortcut::SealVault, &copy, &BTreeMap::new()),
            Some(Shortcut::CopyPassword)
        );
        assert_eq!(clash(Shortcut::CopyPassword, &copy, &BTreeMap::new()), None);
        let moved = overrides(&[("copy-password", "alt-c")]);
        assert_eq!(clash(Shortcut::SealVault, &copy, &moved), None);
    }

    #[test]
    fn resetting_a_shortcut_finds_keys_taken_since() {
        let moved = overrides(&[("seal-vault", "alt-l"), ("new-login", "secondary-l")]);
        let (keys, other) = reset_clash(Shortcut::SealVault, &moved).unwrap();
        assert!(same(&keys, &parse("secondary-l").unwrap()));
        assert_eq!(other, Shortcut::NewLogin);
        assert_eq!(reset_clash(Shortcut::NewLogin, &moved), None);
        assert_eq!(reset_clash(Shortcut::Undo, &BTreeMap::new()), None);
    }

    #[test]
    fn text_editing_keys_are_known() {
        assert!(edits_text(&parse("secondary-a").unwrap()));
        assert!(edits_text(&parse("secondary-shift-z").unwrap()));
        assert!(!edits_text(&parse("secondary-f").unwrap()));
        for keystroke in Shortcut::FocusSearch.keys(&BTreeMap::new()) {
            assert!(!edits_text(&keystroke));
        }
    }

    #[test]
    fn plain_keys_cannot_be_shortcuts() {
        for keys in ["a", "shift-a", "enter", "escape", "down"] {
            assert!(!usable(&parse(keys).unwrap()), "{keys}");
        }
        for keys in ["ctrl-a", "alt-shift-a", "f5", "secondary-,"] {
            assert!(usable(&parse(keys).unwrap()), "{keys}");
        }
        assert_eq!(usable(&parse("cmd-l").unwrap()), cfg!(target_os = "macos"));
        assert!(valid(&overrides(&[("undo", "ctrl-u"), ("redo", "")])));
        assert!(!valid(&overrides(&[("undo", "u")])));
    }
}
