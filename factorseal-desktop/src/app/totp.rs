use hmac::Hmac;
use percent_encoding::percent_decode_str;
use zeroize::Zeroizing;

const SCHEME: &str = "otpauth://totp/";
const PARAMETERS: [&str; 5] = ["secret", "issuer", "algorithm", "digits", "period"];
const IMAGE_SIDE: u32 = 8192;
#[cfg(target_os = "linux")]
const SCREEN_SIDE: u32 = 32768;
const IMAGE_ALLOCATION: u64 = 256 * 1024 * 1024;
const BINARIZE_RADIUS: usize = 8;
const BINARIZE_MARGIN: u32 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Scan {
    NoCode,
    NotOneTime,
}

impl Scan {
    pub(super) fn message(self) -> &'static str {
        match self {
            Self::NoCode => "No QR code found in this image.",
            Self::NotOneTime => "This QR code is not for a one-time password.",
        }
    }
}

pub(super) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[derive(PartialEq)]
pub(super) struct Totp {
    secret: Zeroizing<Vec<u8>>,
    algorithm: Algorithm,
    digits: u32,
    period: u64,
}

impl Totp {
    pub(super) fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        let mut totp = Self {
            secret: Zeroizing::new(Vec::new()),
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
        };
        let secret = if let Some(link) = link(value) {
            let (_, query) = link.split_once('?')?;
            let mut secret = None;
            for (key, value) in query.split('&').filter_map(|pair| pair.split_once('=')) {
                match key {
                    "secret" => secret = Some(decoded(value)?),
                    "algorithm" => {
                        totp.algorithm = match decoded(value)?.to_ascii_uppercase().as_str() {
                            "SHA1" => Algorithm::Sha1,
                            "SHA256" => Algorithm::Sha256,
                            "SHA512" => Algorithm::Sha512,
                            _ => return None,
                        };
                    }
                    "digits" => totp.digits = decoded(value)?.parse().ok()?,
                    "period" => totp.period = decoded(value)?.parse().ok()?,
                    _ => {}
                }
            }
            secret?
        } else {
            Zeroizing::new(value.to_owned())
        };
        totp.secret = Zeroizing::new(
            data_encoding::BASE32_NOPAD
                .decode(base32(&secret).as_bytes())
                .ok()?,
        );
        (!totp.secret.is_empty() && (6..=8).contains(&totp.digits) && totp.period > 0)
            .then_some(totp)
    }

    pub(super) fn period(&self) -> u64 {
        self.period
    }

    pub(super) fn remaining(&self, now: u64) -> u64 {
        self.period - now % self.period
    }

    pub(super) fn code(&self, now: u64) -> Zeroizing<String> {
        let counter = (now / self.period).to_be_bytes();
        let digest = Zeroizing::new(match self.algorithm {
            Algorithm::Sha1 => mac::<Hmac<sha1::Sha1>>(&self.secret, &counter),
            Algorithm::Sha256 => mac::<Hmac<sha2::Sha256>>(&self.secret, &counter),
            Algorithm::Sha512 => mac::<Hmac<sha2::Sha512>>(&self.secret, &counter),
        });
        let offset = usize::from(digest[digest.len() - 1] & 0x0f);
        let binary = u32::from_be_bytes([
            digest[offset] & 0x7f,
            digest[offset + 1],
            digest[offset + 2],
            digest[offset + 3],
        ]);
        let digits = self.digits as usize;
        Zeroizing::new(format!("{:0digits$}", binary % 10_u32.pow(self.digits)))
    }
}

pub(super) fn same_key(first: &str, second: &str) -> bool {
    Totp::parse(first)
        .zip(Totp::parse(second))
        .is_some_and(|(first, second)| first == second)
}

pub(super) fn setup_link(text: &str) -> Option<Zeroizing<String>> {
    let text = text.trim();
    link(text)?;
    normalized(text)
}

pub(super) fn stored(value: &str) -> Result<Zeroizing<String>, String> {
    if value.trim().is_empty() {
        return Ok(Zeroizing::new(String::new()));
    }
    normalized(value).ok_or_else(|| "This is not a valid setup key.".to_owned())
}

fn normalized(value: &str) -> Option<Zeroizing<String>> {
    let value = value.trim();
    Totp::parse(value)?;
    let Some(link) = link(value) else {
        return Some(base32(value));
    };
    let (label, query) = link.split_once('?')?;
    let mut stored = Zeroizing::new(String::with_capacity(value.len()));
    stored.push_str(SCHEME);
    stored.push_str(label);
    let mut separator = '?';
    for (key, value) in query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .filter(|(key, _)| PARAMETERS.contains(key))
    {
        stored.push(separator);
        separator = '&';
        stored.push_str(key);
        stored.push('=');
        if key == "secret" {
            stored.push_str(&base32(&decoded(value)?));
        } else {
            stored.push_str(value);
        }
    }
    Some(stored)
}

pub(super) fn scan(bytes: &[u8]) -> Result<Zeroizing<String>, Scan> {
    scan_within(bytes, IMAGE_SIDE)
}

#[cfg(target_os = "linux")]
pub(super) fn scan_screen(bytes: &[u8]) -> Result<Zeroizing<String>, Scan> {
    scan_within(bytes, SCREEN_SIDE)
}

fn scan_within(bytes: &[u8], side: u32) -> Result<Zeroizing<String>, Scan> {
    let (pixels, width, height) =
        std::panic::catch_unwind(|| luma(bytes, side)).unwrap_or(Err(Scan::NoCode))?;
    scan_luma(&pixels, width, height)
}

type Luma = (Zeroizing<Vec<u8>>, usize, usize);

fn luma(bytes: &[u8], side: u32) -> Result<Luma, Scan> {
    use image::ImageFormat as F;
    let mut reader = image::ImageReader::new(std::io::Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|_| Scan::NoCode)?;
    if !matches!(
        reader.format(),
        Some(F::Png | F::Jpeg | F::Gif | F::WebP | F::Bmp | F::Tiff)
    ) {
        return Err(Scan::NoCode);
    }
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(side);
    limits.max_image_height = Some(side);
    limits.max_alloc = Some(IMAGE_ALLOCATION);
    reader.limits(limits);
    let decoded = reader.decode().map_err(|_| Scan::NoCode)?;
    let picture = decoded.to_luma8();
    wipe(decoded);
    let width = picture.width() as usize;
    let height = picture.height() as usize;
    Ok((Zeroizing::new(picture.into_raw()), width, height))
}

fn wipe(image: image::DynamicImage) {
    use image::DynamicImage as D;
    match image {
        D::ImageLuma16(image) => drop(Zeroizing::new(image.into_raw())),
        D::ImageLumaA16(image) => drop(Zeroizing::new(image.into_raw())),
        D::ImageRgb16(image) => drop(Zeroizing::new(image.into_raw())),
        D::ImageRgba16(image) => drop(Zeroizing::new(image.into_raw())),
        D::ImageRgb32F(image) => drop(Zeroizing::new(image.into_raw())),
        D::ImageRgba32F(image) => drop(Zeroizing::new(image.into_raw())),
        image => drop(Zeroizing::new(image.into_bytes())),
    }
}

pub(super) fn scan_luma(
    pixels: &[u8],
    width: usize,
    height: usize,
) -> Result<Zeroizing<String>, Scan> {
    std::panic::catch_unwind(|| read_luma(pixels, width, height)).unwrap_or(Err(Scan::NoCode))
}

fn read_luma(pixels: &[u8], width: usize, height: usize) -> Result<Zeroizing<String>, Scan> {
    if pixels.len() != width * height {
        return Err(Scan::NoCode);
    }
    let binary = std::cell::OnceCell::new();
    let mut found = false;
    for (binarize, inverted) in [(false, false), (false, true), (true, false), (true, true)] {
        let source = if binarize {
            binary.get_or_init(|| binarized(pixels, width, height))
        } else {
            pixels
        };
        match read_grids(source, width, height, inverted) {
            Ok(link) => return Ok(link),
            Err(Scan::NotOneTime) => found = true,
            Err(Scan::NoCode) => {}
        }
    }
    Err(if found {
        Scan::NotOneTime
    } else {
        Scan::NoCode
    })
}

fn read_grids(
    pixels: &[u8],
    width: usize,
    height: usize,
    inverted: bool,
) -> Result<Zeroizing<String>, Scan> {
    let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(width, height, |x, y| {
        let value = pixels[y * width + x];
        if inverted { u8::MAX - value } else { value }
    });
    let mut found = false;
    for grid in prepared.detect_grids() {
        let mut content = Zeroizing::new(Vec::new());
        if grid.decode_to(&mut *content).is_err() {
            continue;
        }
        found = true;
        if let Some(stored) = std::str::from_utf8(&content)
            .ok()
            .filter(|content| link(content).is_some())
            .and_then(normalized)
        {
            return Ok(stored);
        }
    }
    Err(if found {
        Scan::NotOneTime
    } else {
        Scan::NoCode
    })
}

fn binarized(pixels: &[u8], width: usize, height: usize) -> Zeroizing<Vec<u8>> {
    let mut binary = Zeroizing::new(vec![0; pixels.len()]);
    let mut columns = Zeroizing::new(vec![0_u32; width]);
    let row = |y: usize| &pixels[y * width..(y + 1) * width];
    for y in 0..BINARIZE_RADIUS.min(height) {
        add_row(&mut columns, row(y));
    }
    for y in 0..height {
        if y + BINARIZE_RADIUS < height {
            add_row(&mut columns, row(y + BINARIZE_RADIUS));
        }
        if y > BINARIZE_RADIUS {
            remove_row(&mut columns, row(y - BINARIZE_RADIUS - 1));
        }
        let rows = (y + BINARIZE_RADIUS + 1).min(height) - y.saturating_sub(BINARIZE_RADIUS);
        let mut window: u32 = columns[..BINARIZE_RADIUS.min(width)].iter().sum();
        for x in 0..width {
            if x + BINARIZE_RADIUS < width {
                window += columns[x + BINARIZE_RADIUS];
            }
            if x > BINARIZE_RADIUS {
                window -= columns[x - BINARIZE_RADIUS - 1];
            }
            let wide = (x + BINARIZE_RADIUS + 1).min(width) - x.saturating_sub(BINARIZE_RADIUS);
            let area = u32::try_from(rows * wide).unwrap_or(u32::MAX);
            let value = u32::from(pixels[y * width + x]) + BINARIZE_MARGIN;
            binary[y * width + x] = if value * area < window { 0 } else { u8::MAX };
        }
    }
    binary
}

fn add_row(columns: &mut [u32], row: &[u8]) {
    for (column, &value) in columns.iter_mut().zip(row) {
        *column += u32::from(value);
    }
}

fn remove_row(columns: &mut [u32], row: &[u8]) {
    for (column, &value) in columns.iter_mut().zip(row) {
        *column -= u32::from(value);
    }
}

#[derive(Debug, Default, PartialEq)]
pub(super) struct Origin {
    pub(super) issuer: Option<String>,
    pub(super) account: Option<String>,
}

pub(super) fn origin(value: &str) -> Origin {
    let Some(link) = link(value) else {
        return Origin::default();
    };
    let (label, query) = link.split_once('?').unwrap_or((link, ""));
    let label = decoded(label)
        .map(|label| label.to_string())
        .unwrap_or_default();
    let (named, account) = match label.split_once(':') {
        Some((issuer, account)) => (Some(issuer), account),
        None => (None, label.as_str()),
    };
    let issuer = query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == "issuer")
        .and_then(|(_, value)| decoded(value))
        .map(|issuer| issuer.to_string())
        .or_else(|| named.map(str::to_owned));
    let present = |text: Option<String>| {
        text.map(|text| text.trim().to_owned())
            .filter(|text| !text.is_empty())
    };
    Origin {
        issuer: present(issuer),
        account: present(Some(account.to_owned())),
    }
}

fn link(value: &str) -> Option<&str> {
    value
        .get(..SCHEME.len())
        .filter(|scheme| scheme.eq_ignore_ascii_case(SCHEME))
        .map(|_| &value[SCHEME.len()..])
}

fn decoded(value: &str) -> Option<Zeroizing<String>> {
    let value = percent_decode_str(value).decode_utf8().ok()?;
    Some(Zeroizing::new(value.into_owned()))
}

fn base32(key: &str) -> Zeroizing<String> {
    let mut base32 = Zeroizing::new(String::with_capacity(key.len()));
    base32.extend(
        key.chars()
            .filter(|c| !c.is_whitespace() && !matches!(c, '-' | '='))
            .map(|c| c.to_ascii_uppercase()),
    );
    base32
}

fn mac<M: hmac::Mac + hmac::digest::KeyInit>(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac =
        <M as hmac::digest::KeyInit>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

pub(super) fn grouped(code: &str) -> String {
    let middle = code.len().div_ceil(2);
    format!("{} {}", &code[..middle], &code[middle..])
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_SHA1: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const RFC_SHA256: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
    const RFC_SHA512: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";

    fn uri(secret: &str, algorithm: &str) -> String {
        format!("otpauth://totp/Example:alice?secret={secret}&algorithm={algorithm}&digits=8")
    }

    fn qr_png(content: &str) -> Vec<u8> {
        png(&qr_picture(content, 6, 0, 255))
    }

    fn qr_picture(content: &str, scale: usize, dark: u8, light: u8) -> image::GrayImage {
        let code = qrcode::QrCode::new(content.as_bytes()).unwrap();
        let width = code.width();
        let quiet = 4;
        let side = u32::try_from((width + 2 * quiet) * scale).unwrap();
        image::GrayImage::from_fn(side, side, |x, y| {
            let module = |v: u32| (v as usize / scale).checked_sub(quiet);
            let filled = module(x)
                .zip(module(y))
                .filter(|(x, y)| *x < width && *y < width)
                .is_some_and(|(x, y)| code[(x, y)] == qrcode::Color::Dark);
            image::Luma([if filled { dark } else { light }])
        })
    }

    fn on_page(picture: &image::GrayImage, background: u8) -> image::GrayImage {
        let mut page = image::GrayImage::from_pixel(600, 400, image::Luma([background]));
        image::imageops::overlay(&mut page, picture, 200, 75);
        page
    }

    fn plain_read(picture: &image::GrayImage) -> Result<Zeroizing<String>, Scan> {
        let (width, height) = (picture.width() as usize, picture.height() as usize);
        read_grids(picture.as_raw(), width, height, false)
    }

    fn png(picture: &image::GrayImage) -> Vec<u8> {
        let mut bytes = std::io::Cursor::new(Vec::new());
        picture
            .write_to(&mut bytes, image::ImageFormat::Png)
            .unwrap();
        bytes.into_inner()
    }

    #[test]
    fn codes_match_rfc_6238_vectors() {
        for (now, sha1, sha256, sha512) in [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
        ] {
            let code = |secret, algorithm| {
                Totp::parse(&uri(secret, algorithm))
                    .unwrap()
                    .code(now)
                    .to_string()
            };
            assert_eq!(code(RFC_SHA1, "SHA1"), sha1);
            assert_eq!(code(RFC_SHA256, "SHA256"), sha256);
            assert_eq!(code(RFC_SHA512, "SHA512"), sha512);
        }
    }

    #[test]
    fn bare_secrets_use_six_digits_every_thirty_seconds() {
        let totp = Totp::parse(" gezd gnbv gy3t qojq gezd gnbv gy3t qojq ").unwrap();
        assert_eq!(totp.code(59).as_str(), "287082");
        assert_eq!(totp.period(), 30);
        assert_eq!(totp.remaining(59), 1);
        assert_eq!(totp.remaining(60), 30);
    }

    #[test]
    fn links_accept_an_uppercase_scheme_and_encoded_values() {
        for value in [
            format!("OTPAUTH://TOTP/EXAMPLE?secret={RFC_SHA1}"),
            "otpauth://totp/Example?secret=JBSWY3DPEE%3D%3D%3D%3D%3D%3D".to_owned(),
        ] {
            assert!(Totp::parse(&value).is_some(), "{value}");
        }
        let encoded = format!("otpauth://totp/x?secret={RFC_SHA1}&algorithm=%53HA256&digits=8");
        assert_eq!(
            Totp::parse(&encoded).unwrap().code(59).as_str(),
            Totp::parse(&uri(RFC_SHA1, "SHA256"))
                .unwrap()
                .code(59)
                .as_str()
        );
    }

    #[test]
    fn invalid_values_have_no_code() {
        for value in [
            "",
            "not base32!",
            "otpauth://totp/Example",
            "otpauth://totp/Example?issuer=Example",
            "otpauth://hotp/Example?secret=GEZDGNBV&counter=1",
            &format!("otpauth://totp/x?secret={RFC_SHA1}&algorithm=MD5"),
            &format!("otpauth://totp/x?secret={RFC_SHA1}&digits=4"),
            &format!("otpauth://totp/x?secret={RFC_SHA1}&period=0"),
            &format!("otpauth://totp/x?secret={RFC_SHA1}&period=%FF"),
        ] {
            assert!(Totp::parse(value).is_none(), "{value}");
            assert!(normalized(value).is_none(), "{value}");
        }
    }

    #[test]
    fn links_name_their_issuer_and_account() {
        assert_eq!(
            origin(&format!(
                "otpauth://totp/Example%20Co:alice%40example.com?secret={RFC_SHA1}"
            )),
            Origin {
                issuer: Some("Example Co".into()),
                account: Some("alice@example.com".into()),
            }
        );
        assert_eq!(
            origin(&format!(
                "otpauth://totp/alice?secret={RFC_SHA1}&issuer=GitHub"
            )),
            Origin {
                issuer: Some("GitHub".into()),
                account: Some("alice".into()),
            }
        );
        assert_eq!(origin(RFC_SHA1), Origin::default());
        assert_eq!(
            origin(&format!("otpauth://totp/?secret={RFC_SHA1}")),
            Origin::default()
        );
    }

    #[test]
    fn keys_match_when_they_make_the_same_codes() {
        assert!(same_key(
            "gezd gnbv gy3t qojq gezd gnbv gy3t qojq",
            &format!("otpauth://totp/Example:alice?secret={RFC_SHA1}&digits=6&period=30")
        ));
        assert!(!same_key(RFC_SHA1, &uri(RFC_SHA1, "SHA256")));
        assert!(!same_key(RFC_SHA1, "JBSWY3DPEHPK3PXP"));
        assert!(!same_key("not base32!", "not base32!"));
    }

    #[test]
    fn only_links_that_make_codes_are_setup_links() {
        assert_eq!(
            setup_link(&format!(
                " OTPAUTH://TOTP/Example?secret={}\n",
                RFC_SHA1.to_lowercase()
            ))
            .unwrap()
            .as_str(),
            format!("otpauth://totp/Example?secret={RFC_SHA1}")
        );
        assert!(setup_link(RFC_SHA1).is_none());
        assert!(setup_link("otpauth://totp/Example?secret=not base32!").is_none());
        assert!(setup_link("https://example.com").is_none());
    }

    #[test]
    fn keys_are_stored_without_spaces_padding_or_lowercase() {
        assert_eq!(
            stored(" gezd-gnbv gy3t qojq\tgezd gnbv gy3t qojq== ")
                .unwrap()
                .as_str(),
            RFC_SHA1
        );
        assert_eq!(stored("  ").unwrap().as_str(), "");
        assert!(stored("not base32!").is_err());
    }

    #[test]
    fn links_keep_their_label_and_exchanged_parameters() {
        let stored = normalized(&format!(
            "OTPAUTH://TOTP/Example%20Co:alice%40example.com?secret={}&issuer=Example%20Co&image=https%3A%2F%2Fexample.com%2Fa.png&digits=8&period=60&algorithm=SHA256",
            RFC_SHA1.to_lowercase()
        ))
        .unwrap();
        assert_eq!(
            stored.as_str(),
            format!(
                "otpauth://totp/Example%20Co:alice%40example.com?secret={RFC_SHA1}&issuer=Example%20Co&digits=8&period=60&algorithm=SHA256"
            )
        );
        assert_eq!(normalized(&stored).unwrap(), stored);
    }

    #[test]
    fn pasted_qr_codes_give_their_link() {
        let link = format!("otpauth://totp/Example:alice?secret={RFC_SHA1}&issuer=Example");
        assert_eq!(scan(&qr_png(&link)).unwrap().as_str(), link);
        let messy = format!(
            "otpauth://totp/Example:alice?secret={}",
            RFC_SHA1.to_lowercase()
        );
        assert_eq!(
            scan(&qr_png(&messy)).unwrap().as_str(),
            format!("otpauth://totp/Example:alice?secret={RFC_SHA1}")
        );
    }

    #[test]
    fn light_on_dark_and_small_blurry_qr_codes_give_their_link() {
        let link = format!("otpauth://totp/Example:alice?secret={RFC_SHA1}&issuer=Example");
        let light_on_dark = qr_picture(&link, 6, 235, 20);
        let sharp = qr_picture(&link, 4, 20, 235);
        let blurry = image::imageops::resize(
            &sharp,
            sharp.width() * 3 / 4,
            sharp.height() * 3 / 4,
            image::imageops::FilterType::Triangle,
        );
        for picture in [on_page(&light_on_dark, 20), on_page(&blurry, 235)] {
            assert_eq!(plain_read(&picture).err(), Some(Scan::NoCode));
            assert_eq!(scan(&png(&picture)).unwrap().as_str(), link);
        }
    }

    #[test]
    fn other_qr_codes_and_pictures_have_no_link() {
        assert_eq!(
            scan(&qr_png("https://example.com")).err(),
            Some(Scan::NotOneTime)
        );
        assert_eq!(scan(&qr_png(RFC_SHA1)).err(), Some(Scan::NotOneTime));
        assert_eq!(
            scan(&png(&image::GrayImage::new(64, 64))).err(),
            Some(Scan::NoCode)
        );
        assert_eq!(scan(b"not a picture").err(), Some(Scan::NoCode));
        assert_eq!(
            scan(&png(&image::GrayImage::new(1, 1))).err(),
            Some(Scan::NoCode)
        );
        assert_eq!(
            scan(&png(&image::GrayImage::new(IMAGE_SIDE + 1, 1))).err(),
            Some(Scan::NoCode)
        );
    }

    #[test]
    fn codes_are_split_in_the_middle() {
        assert_eq!(grouped("123456"), "123 456");
        assert_eq!(grouped("1234567"), "1234 567");
        assert_eq!(grouped("12345678"), "1234 5678");
    }
}
