use std::{ffi::CString, ptr::null_mut, str::FromStr};

use derive_more::{Deref, DerefMut};
use zest_pam_core::{
    PamHandle, PamRawErrorCode, PamResult,
    ffi::{pam_conv, pam_end, pam_handle_t, pam_start},
    pam_res_from_code,
};

use crate::{
    PamRawConvImpl,
    conv::{NULL_CONV, PinnedConv},
};

#[derive(Debug, Deref, DerefMut)]
pub struct PamAppHandle<'c, C: PamRawConvImpl = ()> {
    _meta: PinnedConv<'c, C>,
    #[deref]
    #[deref_mut]
    handle: PamHandle,
    end: bool,
}

impl<'c> PamAppHandle<'c, ()> {
    #[inline]
    pub fn start_without_conv(service_name: &str, user: &str) -> PamResult<Self> {
        unsafe { Self::start_with_raw_conv(service_name, user, NULL_CONV.as_ptr()) }
    }

    /// # Safety
    ///
    /// `raw_conv` should be a valid `pam_conv` and kept along with the
    /// lifecycle of the handle.
    #[inline]
    pub unsafe fn start_with_raw_conv(
        service_name: &str,
        user: &str,
        raw_conv: *const pam_conv,
    ) -> PamResult<Self> {
        Self::do_start_with_raw_conv_ptr(service_name, user, unsafe { PinnedConv::raw(raw_conv) })
    }
}

impl<'c, C: PamRawConvImpl> PamAppHandle<'c, C> {
    #[inline]
    pub fn start(service_name: &str, user: &str, conv: &'c mut C) -> PamResult<Self> {
        Self::do_start_with_raw_conv_ptr(service_name, user, PinnedConv::new(conv))
    }

    #[inline]
    pub fn scope<F: FnOnce(&mut Self) -> Result<(), PamRawErrorCode>>(
        mut self,
        func: F,
    ) -> PamResult<()> {
        let res = func(&mut self);
        self.end(match res {
            Ok(()) => PamRawErrorCode::Success,
            Err(code) => code,
        })
    }

    #[inline]
    pub fn end(mut self, code: PamRawErrorCode) -> PamResult<()> {
        self.do_end(code)
    }

    fn do_start_with_raw_conv_ptr(
        service_name: &str,
        user: &str,
        meta: PinnedConv<'c, C>,
    ) -> PamResult<Self> {
        let service_name = CString::from_str(service_name)?;
        let user = CString::from_str(user)?;

        let mut pamh = null_mut::<pam_handle_t>();
        unsafe {
            pam_res_from_code(pam_start(
                service_name.as_ptr(),
                user.as_ptr(),
                meta.as_ptr(),
                &mut pamh,
            ))?;
        }

        Ok(Self {
            handle: unsafe { PamHandle::from_ptr(pamh.cast())? },
            _meta: meta,
            end: false,
        })
    }

    #[inline]
    fn do_end(&mut self, code: PamRawErrorCode) -> PamResult<()> {
        if !self.end {
            self.end = true;
            pam_res_from_code(unsafe { pam_end(self.as_ptr_mut().cast(), code as _) })?;
        }
        Ok(())
    }
}

impl<'c, C: PamRawConvImpl> Drop for PamAppHandle<'c, C> {
    #[inline]
    fn drop(&mut self) {
        let _ = self.do_end(PamRawErrorCode::Abort);
    }
}
