use crate::api::{Revealed, Scan};
use factorseal::personal::{qr, totp};
use zeroize::Zeroizing;

const PAIRING_PREFIX: &str = "factorseal-sync:";
const MAX_SIDE: usize = 4096;

pub(crate) fn scan(pixels: &[u8], width: usize, height: usize, stride: usize) -> Scan {
    if width == 0
        || height == 0
        || width > MAX_SIDE
        || height > MAX_SIDE
        || stride < width
        || pixels.len() < stride * (height - 1) + width
    {
        return Scan::Nothing;
    }
    let mut packed = Zeroizing::new(Vec::with_capacity(width * height));
    for row in pixels.chunks(stride).take(height) {
        packed.extend_from_slice(&row[..width]);
    }
    qr::read(&packed, width, height, recognize).unwrap_or_else(|miss| match miss {
        qr::Miss::NoCode => Scan::Nothing,
        qr::Miss::Unrecognized => Scan::Unsupported,
    })
}

pub(crate) fn classify(text: &str) -> Scan {
    let text = text.trim();
    if text.is_empty() {
        Scan::Nothing
    } else {
        recognize(text).unwrap_or(Scan::Unsupported)
    }
}

fn recognize(text: &str) -> Option<Scan> {
    let text = text.trim();
    if text.starts_with(PAIRING_PREFIX) {
        return Some(Scan::Pairing {
            ticket: Revealed(Zeroizing::new(text.to_owned())),
        });
    }
    let value = totp::setup_link(text)?;
    let origin = totp::origin(&value);
    Some(Scan::OneTimePassword {
        value: Revealed(value),
        issuer: origin.issuer,
        account: origin.account,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn frame(
        content: &str,
        scale: usize,
        dark: u8,
        light: u8,
        stride_padding: usize,
    ) -> (Vec<u8>, usize, usize, usize) {
        let code = qrcode::QrCode::new(content.as_bytes()).unwrap();
        let modules = code.width();
        let quiet = 4;
        let side = (modules + 2 * quiet) * scale;
        let stride = side + stride_padding;
        let mut pixels = vec![light; stride * side];
        for y in 0..side {
            for x in 0..side {
                let module = |v: usize| (v / scale).checked_sub(quiet);
                let filled = module(x)
                    .zip(module(y))
                    .filter(|(x, y)| *x < modules && *y < modules)
                    .is_some_and(|(x, y)| code[(x, y)] == qrcode::Color::Dark);
                if filled {
                    pixels[y * stride + x] = dark;
                }
            }
        }
        (pixels, side, side, stride)
    }

    #[test]
    fn camera_frames_find_pairing_codes_and_setup_links() {
        let ticket = format!("factorseal-sync:1:{}", "A".repeat(182));
        let (pixels, width, height, stride) = frame(&ticket, 4, 20, 235, 16);
        let Scan::Pairing { ticket: found } = scan(&pixels, width, height, stride) else {
            panic!("expected a pairing code");
        };
        assert_eq!(found.0.as_str(), ticket);

        let link = format!(
            "otpauth://totp/Example:alice?secret={}&issuer=Example",
            SECRET.to_lowercase()
        );
        let (pixels, width, height, stride) = frame(&link, 4, 235, 20, 0);
        let Scan::OneTimePassword {
            value,
            issuer,
            account,
        } = scan(&pixels, width, height, stride)
        else {
            panic!("expected a one-time password");
        };
        assert_eq!(
            value.0.as_str(),
            format!("otpauth://totp/Example:alice?secret={SECRET}&issuer=Example")
        );
        assert_eq!(issuer.as_deref(), Some("Example"));
        assert_eq!(account.as_deref(), Some("alice"));
    }

    #[test]
    fn other_codes_and_empty_frames_are_reported() {
        let (pixels, width, height, stride) = frame("https://example.com", 4, 20, 235, 0);
        assert!(matches!(
            scan(&pixels, width, height, stride),
            Scan::Unsupported
        ));
        assert!(matches!(scan(&[128; 64 * 64], 64, 64, 64), Scan::Nothing));
        assert!(matches!(scan(&[0; 10], 64, 64, 64), Scan::Nothing));
        assert!(matches!(scan(&[0; 64], 8, 8, 4), Scan::Nothing));
    }
}
