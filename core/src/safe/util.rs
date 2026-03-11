use core::{ffi::CStr, mem::forget, ops::Deref, ptr::NonNull};

use alloc::{borrow::ToOwned, ffi::CString, string::String};
use libc::free;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::PamUtf8Error;

/// No credential data after the null byte.
#[derive(Debug)]
pub struct SafeCString {
    value: CString,
    len: usize,
}

impl SafeCString {
    #[inline]
    pub(crate) const fn new(value: CString, len: usize) -> Self {
        Self { value, len }
    }

    #[inline]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn try_into_string(self) -> Result<Zeroizing<String>, PamUtf8Error> {
        self.to_str()
            .map(|s| Zeroizing::new(s.to_owned()))
            .map_err(|e| PamUtf8Error {
                value: self,
                err: e,
            })
    }
}

impl Zeroize for SafeCString {
    #[inline]
    fn zeroize(&mut self) {
        let ptr = self.value.as_ptr();
        let raw_bytes = unsafe { core::slice::from_raw_parts_mut(ptr.cast_mut(), self.len) };
        raw_bytes.zeroize();
    }
}

impl Deref for SafeCString {
    type Target = CStr;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.value.as_c_str()
    }
}

impl Drop for SafeCString {
    #[inline]
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SafeCString {}

#[doc(hidden)]
pub struct LibCDropGuard<T>(NonNull<T>, usize);

impl<T> LibCDropGuard<T> {
    #[inline]
    pub const fn new(ptr: NonNull<T>, size: usize) -> Self {
        Self(ptr, size)
    }

    #[inline]
    pub const fn defuse(self) {
        forget(self);
    }
}

impl<T> Drop for LibCDropGuard<T> {
    fn drop(&mut self) {
        let ptr = self.0.as_ptr().cast::<i8>();
        let raw_bytes = unsafe { core::slice::from_raw_parts_mut(ptr, self.1) };
        raw_bytes.zeroize();
        unsafe {
            free(self.0.as_ptr().cast());
        }
    }
}
