use windows_sys::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, BitBlt, CAPTUREBLT, CreateCompatibleBitmap,
    CreateCompatibleDC, DIB_RGB_COLORS, DeleteDC, DeleteObject, GetDC, GetDIBits, RGBQUAD,
    ReleaseDC, SRCCOPY, SelectObject,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
};
use zeroize::Zeroizing;

pub(super) fn capture() -> Option<(Zeroizing<Vec<u8>>, usize, usize)> {
    let colors = capture_colors()?;
    let (pixels, width, height) = &colors;
    let luma = pixels
        .as_chunks::<4>()
        .0
        .iter()
        .map(|pixel| {
            let [blue, green, red, _] = pixel.map(u32::from);
            u8::try_from((red * 299 + green * 587 + blue * 114) / 1000).unwrap_or(u8::MAX)
        })
        .collect();
    Some((Zeroizing::new(luma), *width, *height))
}

#[allow(unsafe_code)]
fn capture_colors() -> Option<(Zeroizing<Vec<u8>>, usize, usize)> {
    let (left, top, width, height) = unsafe {
        (
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN),
            GetSystemMetrics(SM_CXVIRTUALSCREEN),
            GetSystemMetrics(SM_CYVIRTUALSCREEN),
        )
    };
    let columns = usize::try_from(width).ok().filter(|columns| *columns > 0)?;
    let rows = usize::try_from(height).ok().filter(|rows| *rows > 0)?;
    let mut pixels = Zeroizing::new(vec![0_u8; columns * rows * 4]);
    let mut info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: u32::try_from(size_of::<BITMAPINFOHEADER>()).ok()?,
            biWidth: width,
            biHeight: -height,
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB,
            biSizeImage: 0,
            biXPelsPerMeter: 0,
            biYPelsPerMeter: 0,
            biClrUsed: 0,
            biClrImportant: 0,
        },
        bmiColors: [RGBQUAD::default()],
    };
    let lines = unsafe {
        let screen = GetDC(std::ptr::null_mut());
        let memory = CreateCompatibleDC(screen);
        let bitmap = CreateCompatibleBitmap(screen, width, height);
        let previous = SelectObject(memory, bitmap);
        let copied = BitBlt(
            memory,
            0,
            0,
            width,
            height,
            screen,
            left,
            top,
            SRCCOPY | CAPTUREBLT,
        );
        SelectObject(memory, previous);
        let lines = if copied == 0 {
            0
        } else {
            GetDIBits(
                memory,
                bitmap,
                0,
                u32::try_from(height).unwrap_or_default(),
                pixels.as_mut_ptr().cast(),
                &raw mut info,
                DIB_RGB_COLORS,
            )
        };
        DeleteObject(bitmap);
        DeleteDC(memory);
        ReleaseDC(std::ptr::null_mut(), screen);
        lines
    };
    (lines == height).then_some((pixels, columns, rows))
}
