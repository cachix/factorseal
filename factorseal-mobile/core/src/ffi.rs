#![allow(unsafe_code)]

use zeroize::Zeroize as _;

#[repr(C)]
pub struct FactorSealBuffer {
    pub data: *mut u8,
    pub length: usize,
}

impl FactorSealBuffer {
    fn new(bytes: &[u8]) -> Self {
        let boxed: Box<[u8]> = bytes.into();
        let length = boxed.len();
        Self {
            data: Box::into_raw(boxed).cast::<u8>(),
            length,
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn factorseal_call(request: *const u8, length: usize) -> FactorSealBuffer {
    let request = if request.is_null() || length == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(request, length) }
    };
    FactorSealBuffer::new(&crate::call(request))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn factorseal_scan(
    pixels: *const u8,
    length: usize,
    width: usize,
    height: usize,
    stride: usize,
) -> FactorSealBuffer {
    let pixels = if pixels.is_null() || length == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(pixels, length) }
    };
    FactorSealBuffer::new(&crate::scan(pixels, width, height, stride))
}

#[unsafe(no_mangle)]
pub extern "C" fn factorseal_seal() {
    crate::seal();
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn factorseal_free(buffer: FactorSealBuffer) {
    if buffer.data.is_null() {
        return;
    }
    let mut boxed = unsafe {
        Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            buffer.data,
            buffer.length,
        ))
    };
    boxed.zeroize();
}
