use std::sync::Arc;

use crate::{Error, Result};

/// A platform-neutral tray icon stored as non-premultiplied RGBA8 pixels.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Icon {
    rgba: Arc<[u8]>,
    width: u32,
    height: u32,
}

impl Icon {
    /// Creates an icon from tightly packed, row-major RGBA8 pixels.
    pub fn from_rgba(rgba: impl Into<Arc<[u8]>>, width: u32, height: u32) -> Result<Self> {
        let rgba = rgba.into();
        let expected = width
            .checked_mul(height)
            .and_then(|pixels| pixels.checked_mul(4))
            .and_then(|bytes| usize::try_from(bytes).ok())
            .ok_or_else(|| Error::InvalidIcon("dimensions overflow".into()))?;

        if width == 0 || height == 0 {
            return Err(Error::InvalidIcon("dimensions must be non-zero".into()));
        }
        if rgba.len() != expected {
            return Err(Error::InvalidIcon(format!(
                "expected {expected} RGBA bytes for {width}x{height}, got {}",
                rgba.len()
            )));
        }

        Ok(Self {
            rgba,
            width,
            height,
        })
    }

    /// Renders the first frame of a GPUI image into normalized RGBA8 pixels.
    /// Raster formats and SVG are handled by GPUI's own image pipeline.
    pub fn from_gpui(image: &gpui::Image, cx: &gpui::App) -> Result<Self> {
        let rendered = image
            .to_image_data(cx.svg_renderer())
            .map_err(|error| Error::InvalidIcon(error.to_string()))?;
        let size = rendered.size(0);
        let mut rgba = rendered
            .as_bytes(0)
            .ok_or_else(|| Error::InvalidIcon("GPUI image has no frames".into()))?
            .to_vec();
        // GPUI render images are BGRA; native backends receive normalized RGBA.
        for pixel in rgba.chunks_exact_mut(4) {
            pixel.swap(0, 2);
        }
        Self::from_rgba(rgba, size.width.into(), size.height.into())
    }

    pub(crate) fn rgba(&self) -> &[u8] {
        &self.rgba
    }

    pub(crate) const fn width(&self) -> u32 {
        self.width
    }

    pub(crate) const fn height(&self) -> u32 {
        self.height
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_pixel_length() {
        assert!(Icon::from_rgba(vec![0; 16], 2, 2).is_ok());
        assert!(Icon::from_rgba(vec![0; 15], 2, 2).is_err());
        assert!(Icon::from_rgba(Vec::<u8>::new(), 0, 0).is_err());
    }
}
