use core::{
    borrow::Borrow,
    ops::{Deref, DerefMut},
    ptr::NonNull,
};

use crate::{PamError, PamResult, ffi::pam_handle_t};

#[derive(Debug)]
pub enum PamRawHandle {}

#[must_use]
#[derive(Debug)]
pub struct PamHandle {
    ptr: NonNull<PamRawHandle>,
}

impl PamHandle {
    /// # Safety
    ///
    /// The lifecycle of the raw handle won't be managed by `PamHandle`.
    #[inline]
    pub const unsafe fn new(ptr: NonNull<PamRawHandle>) -> Self {
        Self { ptr }
    }

    /// # Safety
    ///
    /// The lifecycle of the raw handle won't be managed by `PamHandle`.
    #[inline]
    pub unsafe fn from_ptr(ptr: *mut PamRawHandle) -> PamResult<Self> {
        let ptr = NonNull::new(ptr).ok_or(PamError::PamHandleNullPtr)?;
        Ok(unsafe { Self::new(ptr) })
    }

    /// # Safety
    ///
    /// `ptr` must be non-null. The lifecycle of the raw handle won't be managed
    /// by `PamHandle`.
    #[inline]
    pub const unsafe fn from_ptr_uncheck(ptr: *mut PamRawHandle) -> Self {
        unsafe { Self::new(NonNull::new_unchecked(ptr)) }
    }

    /// # Safety
    ///
    /// `ptr` shall not be passed around.
    #[inline]
    pub const unsafe fn as_ptr_mut(&mut self) -> *mut PamRawHandle {
        self.ptr.as_ptr()
    }

    #[inline]
    pub const fn as_ptr(&self) -> *const PamRawHandle {
        self.ptr.as_ptr()
    }

    #[inline]
    pub const fn into_ptr(self) -> NonNull<PamRawHandle> {
        self.ptr
    }
}

impl Deref for PamHandle {
    type Target = PamRawHandle;

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

impl AsRef<PamRawHandle> for PamHandle {
    #[inline]
    fn as_ref(&self) -> &PamRawHandle {
        self
    }
}

impl AsMut<PamRawHandle> for PamHandle {
    #[inline]
    fn as_mut(&mut self) -> &mut PamRawHandle {
        self
    }
}

impl Borrow<PamRawHandle> for PamHandle {
    #[inline]
    fn borrow(&self) -> &PamRawHandle {
        self
    }
}

impl From<&PamRawHandle> for *const pam_handle_t {
    #[inline]
    fn from(value: &PamRawHandle) -> Self {
        (value as *const PamRawHandle).cast()
    }
}

impl From<&mut PamRawHandle> for *mut pam_handle_t {
    #[inline]
    fn from(value: &mut PamRawHandle) -> Self {
        (value as *mut PamRawHandle).cast()
    }
}

impl From<PamHandle> for NonNull<PamRawHandle> {
    #[inline]
    fn from(handle: PamHandle) -> Self {
        handle.into_ptr()
    }
}
