use zeroize::Zeroizing;

const BINARIZE_RADIUS: usize = 8;
const BINARIZE_MARGIN: u32 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Miss {
    NoCode,
    Unrecognized,
}

pub fn read<T>(
    pixels: &[u8],
    width: usize,
    height: usize,
    mut recognize: impl FnMut(&str) -> Option<T>,
) -> Result<T, Miss> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        read_luma(pixels, width, height, &mut recognize)
    }))
    .unwrap_or(Err(Miss::NoCode))
}

fn read_luma<T>(
    pixels: &[u8],
    width: usize,
    height: usize,
    recognize: &mut impl FnMut(&str) -> Option<T>,
) -> Result<T, Miss> {
    if width.checked_mul(height) != Some(pixels.len()) {
        return Err(Miss::NoCode);
    }
    let binary = std::cell::OnceCell::new();
    let mut found = false;
    for (binarize, inverted) in [(false, false), (false, true), (true, false), (true, true)] {
        let source = if binarize {
            binary.get_or_init(|| binarized(pixels, width, height))
        } else {
            pixels
        };
        match read_grids(source, width, height, inverted, recognize) {
            Ok(value) => return Ok(value),
            Err(Miss::Unrecognized) => found = true,
            Err(Miss::NoCode) => {}
        }
    }
    Err(if found {
        Miss::Unrecognized
    } else {
        Miss::NoCode
    })
}

fn read_grids<T>(
    pixels: &[u8],
    width: usize,
    height: usize,
    inverted: bool,
    recognize: &mut impl FnMut(&str) -> Option<T>,
) -> Result<T, Miss> {
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
        if let Some(value) = std::str::from_utf8(&content).ok().and_then(&mut *recognize) {
            return Ok(value);
        }
    }
    Err(if found {
        Miss::Unrecognized
    } else {
        Miss::NoCode
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

#[cfg(test)]
mod tests {
    use super::*;

    fn picture(content: &str, scale: usize, dark: u8, light: u8) -> (Vec<u8>, usize) {
        let code = qrcode::QrCode::new(content.as_bytes()).unwrap();
        let modules = code.width();
        let quiet = 4;
        let side = (modules + 2 * quiet) * scale;
        let mut pixels = vec![light; side * side];
        for y in 0..side {
            for x in 0..side {
                let module = |v: usize| (v / scale).checked_sub(quiet);
                let filled = module(x)
                    .zip(module(y))
                    .filter(|(x, y)| *x < modules && *y < modules)
                    .is_some_and(|(x, y)| code[(x, y)] == qrcode::Color::Dark);
                if filled {
                    pixels[y * side + x] = dark;
                }
            }
        }
        (pixels, side)
    }

    fn accept(text: &str) -> Option<String> {
        text.starts_with("accept:").then(|| text.to_owned())
    }

    #[test]
    fn codes_are_read_dark_on_light_and_light_on_dark() {
        for (dark, light) in [(20, 235), (235, 20)] {
            let (pixels, side) = picture("accept:code", 6, dark, light);
            assert_eq!(
                read(&pixels, side, side, accept).as_deref(),
                Ok("accept:code")
            );
        }
        let (pixels, side) = picture("accept:code", 6, 235, 20);
        let mut plain = |text: &str| accept(text);
        assert_eq!(
            read_grids(&pixels, side, side, false, &mut plain),
            Err(Miss::NoCode)
        );
    }

    #[test]
    fn unrecognized_codes_and_empty_pictures_are_told_apart() {
        let (pixels, side) = picture("https://example.com", 6, 20, 235);
        assert_eq!(read(&pixels, side, side, accept), Err(Miss::Unrecognized));
        assert_eq!(read(&[128; 64 * 64], 64, 64, accept), Err(Miss::NoCode));
        assert_eq!(read(&[0; 10], 64, 64, accept), Err(Miss::NoCode));
    }
}
