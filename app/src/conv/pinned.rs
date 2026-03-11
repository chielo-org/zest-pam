use std::{marker::PhantomData, ptr::NonNull};

use zest_pam_core::ffi::pam_conv;

use crate::{PamRawConvImpl, conv::callback::pam_raw_conv_callback};

#[derive(Debug)]
pub(crate) struct PinnedConv<'c, C> {
    ptr: *const pam_conv,
    meta: Option<NonNull<pam_conv>>,
    data: PhantomData<&'c mut C>,
}

impl<'c, C: PamRawConvImpl> PinnedConv<'c, C> {
    #[inline]
    pub fn new(data: &'c mut C) -> Self {
        Self::owned(
            pam_conv {
                conv: Some(pam_raw_conv_callback),
                appdata_ptr: (data as *mut C).cast(),
            },
            data,
        )
    }
}

impl<'c, C> PinnedConv<'c, C> {
    #[inline]
    fn owned(conv: pam_conv, _data: &'c mut C) -> Self {
        let meta = NonNull::from(Box::leak(Box::new(conv)));
        Self {
            ptr: meta.as_ptr(),
            meta: Some(meta),
            data: PhantomData,
        }
    }

    #[inline]
    pub const unsafe fn raw(ptr: *const pam_conv) -> Self {
        Self {
            ptr,
            meta: None,
            data: PhantomData,
        }
    }

    #[inline]
    pub const unsafe fn as_ptr(&self) -> *const pam_conv {
        self.ptr
    }
}

impl<'c, C> Drop for PinnedConv<'c, C> {
    #[inline]
    fn drop(&mut self) {
        if let Some(ptr) = self.meta.take() {
            drop(Box::from(ptr));
        }
    }
}
