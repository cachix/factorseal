use std::ops::RangeInclusive;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const LENGTHS: RangeInclusive<u8> = 8..=64;
pub const WORD_COUNTS: RangeInclusive<u8> = 12..=24;
pub const WORD_STEP: u8 = 3;

const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!#$%&*+-=?@^_";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Style {
    Random,
    #[default]
    Words,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Options {
    pub style: Style,
    pub length: u8,
    pub words: u8,
    pub digits: bool,
    pub symbols: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            style: Style::default(),
            length: 20,
            words: 12,
            digits: true,
            symbols: true,
        }
    }
}

impl Options {
    #[must_use]
    pub fn is_valid(self) -> bool {
        LENGTHS.contains(&self.length)
            && WORD_COUNTS.contains(&self.words)
            && (self.words - WORD_COUNTS.start()).is_multiple_of(WORD_STEP)
    }

    #[must_use]
    pub fn strength(self) -> Strength {
        let bits = match self.style {
            Style::Words => f64::from(self.words) * 11. * 32. / 33.,
            Style::Random => {
                let alphabet = self
                    .classes()
                    .iter()
                    .map(|class| class.len())
                    .sum::<usize>();
                f64::from(self.length) * f64::from(u32::try_from(alphabet).unwrap_or(1)).log2()
            }
        };
        Strength::from_bits(bits)
    }

    fn classes(self) -> Vec<&'static [u8]> {
        [
            Some(LOWERCASE),
            Some(UPPERCASE),
            self.digits.then_some(DIGITS),
            self.symbols.then_some(SYMBOLS),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strength {
    Weak,
    Good,
    Strong,
}

impl Strength {
    #[must_use]
    pub fn of(password: &str) -> Self {
        match crate::security::password_score(password) {
            0..=2 => Self::Weak,
            3 => Self::Good,
            _ => Self::Strong,
        }
    }

    fn from_bits(bits: f64) -> Self {
        if bits < 60. {
            Self::Weak
        } else if bits < 80. {
            Self::Good
        } else {
            Self::Strong
        }
    }

    #[must_use]
    pub fn level(self) -> usize {
        match self {
            Self::Weak => 1,
            Self::Good => 2,
            Self::Strong => 3,
        }
    }
}

pub fn generate(options: Options) -> Result<Zeroizing<String>, getrandom::Error> {
    generate_with(options, getrandom::fill)
}

fn generate_with(
    options: Options,
    mut fill: impl FnMut(&mut [u8]) -> Result<(), getrandom::Error>,
) -> Result<Zeroizing<String>, getrandom::Error> {
    match options.style {
        Style::Words => {
            let mut entropy = Zeroizing::new([0_u8; 32]);
            let entropy = &mut entropy[..usize::from(options.words) * 4 / 3];
            fill(entropy)?;
            Ok(passphrase_from_entropy(entropy))
        }
        Style::Random => random_password(options, &mut fill),
    }
}

fn passphrase_from_entropy(entropy: &[u8]) -> Zeroizing<String> {
    let mnemonic = bip39::Mnemonic::from_entropy(entropy)
        .expect("word counts map to valid BIP-39 entropy lengths");
    Zeroizing::new(mnemonic.to_string())
}

fn random_password(
    options: Options,
    fill: &mut impl FnMut(&mut [u8]) -> Result<(), getrandom::Error>,
) -> Result<Zeroizing<String>, getrandom::Error> {
    let classes = options.classes();
    let alphabet: Vec<u8> = classes.concat();
    loop {
        let mut password = Zeroizing::new(String::with_capacity(usize::from(options.length)));
        for _ in 0..options.length {
            password.push(char::from(alphabet[uniform_index(alphabet.len(), fill)?]));
        }
        if classes
            .iter()
            .all(|class| password.bytes().any(|byte| class.contains(&byte)))
        {
            return Ok(password);
        }
    }
}

fn uniform_index(
    count: usize,
    fill: &mut impl FnMut(&mut [u8]) -> Result<(), getrandom::Error>,
) -> Result<usize, getrandom::Error> {
    let limit = 256 - 256 % count;
    loop {
        let mut byte = Zeroizing::new([0_u8; 1]);
        fill(&mut *byte)?;
        let value = usize::from(byte[0]);
        if value < limit {
            return Ok(value % count);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counter() -> impl FnMut(&mut [u8]) -> Result<(), getrandom::Error> {
        let mut next = 0_u8;
        move |bytes| {
            for byte in bytes {
                *byte = next;
                next = next.wrapping_add(7);
            }
            Ok(())
        }
    }

    fn random(length: u8, digits: bool, symbols: bool) -> Options {
        Options {
            style: Style::Random,
            length,
            digits,
            symbols,
            ..Options::default()
        }
    }

    #[test]
    fn defaults_keep_the_twelve_word_passphrase() {
        let options = Options::default();
        assert!(options.is_valid());
        let first = generate(options).unwrap();
        let second = generate(options).unwrap();
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

    #[test]
    fn every_word_count_makes_a_valid_passphrase_of_that_length() {
        for words in WORD_COUNTS.step_by(usize::from(WORD_STEP)) {
            let options = Options {
                words,
                ..Options::default()
            };
            assert!(options.is_valid());
            let phrase = generate(options).unwrap();
            assert_eq!(phrase.split_whitespace().count(), usize::from(words));
            assert!(bip39::Mnemonic::parse_in(bip39::Language::English, &*phrase).is_ok());
        }
    }

    #[test]
    fn random_passwords_have_the_length_and_every_chosen_kind_of_character() {
        for length in LENGTHS {
            for (digits, symbols) in [(false, false), (true, false), (false, true), (true, true)] {
                let password = generate(random(length, digits, symbols)).unwrap();
                assert_eq!(password.len(), usize::from(length));
                assert!(password.bytes().any(|byte| LOWERCASE.contains(&byte)));
                assert!(password.bytes().any(|byte| UPPERCASE.contains(&byte)));
                assert_eq!(password.bytes().any(|byte| DIGITS.contains(&byte)), digits);
                assert_eq!(
                    password.bytes().any(|byte| SYMBOLS.contains(&byte)),
                    symbols
                );
            }
        }
    }

    #[test]
    fn random_passwords_are_deterministic_for_the_same_bytes() {
        let options = random(16, true, true);
        let first = generate_with(options, counter()).unwrap();
        let second = generate_with(options, counter()).unwrap();
        assert_eq!(*first, *second);
        assert_ne!(*first, *generate(options).unwrap());
    }

    #[test]
    fn uniform_index_rejects_bytes_that_would_bias_the_result() {
        let mut bytes = [252_u8, 255, 7].into_iter();
        let mut fill = |buffer: &mut [u8]| {
            buffer[0] = bytes.next().unwrap();
            Ok(())
        };
        assert_eq!(uniform_index(36, &mut fill).unwrap(), 7);
    }

    #[test]
    fn invalid_lengths_and_word_counts_are_rejected() {
        for options in [
            random(7, true, true),
            random(65, true, true),
            Options {
                words: 13,
                ..Options::default()
            },
            Options {
                words: 27,
                ..Options::default()
            },
        ] {
            assert!(!options.is_valid());
        }
    }

    #[test]
    fn options_round_trip_and_fill_missing_fields_with_defaults() {
        let options = random(32, false, true);
        let json = serde_json::to_string(&options).unwrap();
        assert_eq!(serde_json::from_str::<Options>(&json).unwrap(), options);
        assert_eq!(
            serde_json::from_str::<Options>(r#"{"style":"random"}"#).unwrap(),
            Options {
                style: Style::Random,
                ..Options::default()
            }
        );
    }

    #[test]
    fn generated_strength_follows_the_options_entropy() {
        assert_eq!(Strength::from_bits(59.9), Strength::Weak);
        assert_eq!(Strength::from_bits(60.), Strength::Good);
        assert_eq!(Strength::from_bits(80.), Strength::Strong);
        for (options, strength) in [
            (random(*LENGTHS.start(), false, false), Strength::Weak),
            (random(*LENGTHS.start(), true, true), Strength::Weak),
            (random(12, false, false), Strength::Good),
            (random(12, true, true), Strength::Good),
            (random(16, false, false), Strength::Strong),
            (random(*LENGTHS.end(), true, true), Strength::Strong),
            (Options::default(), Strength::Strong),
        ] {
            assert!(options.is_valid());
            assert_eq!(options.strength(), strength);
        }
    }

    #[test]
    fn strength_follows_the_vault_password_policy() {
        assert_eq!(Strength::of("password"), Strength::Weak);
        assert_ne!(
            Strength::of("opal nebula lantern saffron velocity"),
            Strength::Weak
        );
        let generated = generate(Options::default()).unwrap();
        assert_eq!(Strength::of(&generated), Strength::Strong);
    }
}
