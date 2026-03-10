use core::{
    borrow::Borrow,
    ops::{Deref, DerefMut},
    ptr::NonNull,
};

use crate::{PamError, PamResult, ffi::pam_handle_t};

pub enum RawPamHandle {}

#[must_use]
pub struct PamHandle {
    ptr: NonNull<RawPamHandle>,
}

impl PamHandle {
    /// # Safety
    ///
    ///  The lifecycle of the raw handle won't be managed by `PamHandle`.
    #[inline]
    pub const unsafe fn new(ptr: NonNull<RawPamHandle>) -> Self {
        Self { ptr }
    }

    /// # Safety
    ///
    /// `ptr` must be non-null. The lifecycle of the raw handle won't be managed
    /// by `PamHandle`.
    #[inline]
    pub unsafe fn from_ptr(ptr: *mut RawPamHandle) -> PamResult<Self> {
        let ptr = NonNull::new(ptr).ok_or(PamError::PamHandleNullPtr)?;
        Ok(unsafe { Self::new(ptr) })
    }

    /// # Safety
    ///
    /// `ptr` must be non-null. The lifecycle of the raw handle won't be managed
    /// by `PamHandle`.
    #[inline]
    pub const unsafe fn from_ptr_uncheck(ptr: *mut RawPamHandle) -> Self {
        unsafe { Self::new(NonNull::new_unchecked(ptr)) }
    }

    #[inline]
    pub const fn as_ptr(&self) -> *const RawPamHandle {
        self.ptr.as_ptr()
    }

    #[inline]
    pub const fn into_ptr(self) -> NonNull<RawPamHandle> {
        self.ptr
    }
}

impl Deref for PamHandle {
    type Target = RawPamHandle;

    #[inline]
    fn deref(&self) -> &Self::Target {
        unsafe { self.ptr.as_ref() }
    }
}

impl DerefMut for PamHandle {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.ptr.as_mut() }
    }
}

impl AsRef<RawPamHandle> for PamHandle {
    #[inline]
    fn as_ref(&self) -> &RawPamHandle {
        self
    }
}

impl AsMut<RawPamHandle> for PamHandle {
    #[inline]
    fn as_mut(&mut self) -> &mut RawPamHandle {
        self
    }
}

impl Borrow<RawPamHandle> for PamHandle {
    #[inline]
    fn borrow(&self) -> &RawPamHandle {
        self
    }
}

impl From<&RawPamHandle> for *const pam_handle_t {
    #[inline]
    fn from(value: &RawPamHandle) -> Self {
        (value as *const RawPamHandle).cast()
    }
}

impl From<&mut RawPamHandle> for *mut pam_handle_t {
    #[inline]
    fn from(value: &mut RawPamHandle) -> Self {
        (value as *mut RawPamHandle).cast()
    }
}

impl From<PamHandle> for NonNull<RawPamHandle> {
    #[inline]
    fn from(handle: PamHandle) -> Self {
        handle.into_ptr()
    }
}
