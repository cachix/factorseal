use factorseal::personal::qr;
use zeroize::Zeroizing;

pub(super) use factorseal::personal::totp::{
    Origin, Totp, grouped, origin, same_key, setup_link, unix_now,
};

const IMAGE_SIDE: u32 = 8192;
#[cfg(target_os = "linux")]
const SCREEN_SIDE: u32 = 32768;
const IMAGE_ALLOCATION: u64 = 256 * 1024 * 1024;

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

pub(super) fn stored(value: &str) -> Result<Zeroizing<String>, String> {
    factorseal::personal::totp::stored(value)
        .ok_or_else(|| "This is not a valid setup key.".to_owned())
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
    qr::read(pixels, width, height, setup_link).map_err(|miss| match miss {
        qr::Miss::NoCode => Scan::NoCode,
        qr::Miss::Unrecognized => Scan::NotOneTime,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_SHA1: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

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

    fn png(picture: &image::GrayImage) -> Vec<u8> {
        let mut bytes = std::io::Cursor::new(Vec::new());
        picture
            .write_to(&mut bytes, image::ImageFormat::Png)
            .unwrap();
        bytes.into_inner()
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
}
