use std::{
    ffi::CString,
    marker::PhantomData,
    ptr::{NonNull, null_mut},
    str::FromStr,
};

use derive_more::{Deref, DerefMut};
use zest_pam_core::{
    PamHandle, PamRawErrorCode, PamResult,
    ffi::{pam_conv, pam_end, pam_handle_t, pam_start},
    pam_res_from_code,
};

use crate::{PamRawConvImpl, null_conv::NULL_CONV, raw_conv::custom_conv_callback};

#[derive(Debug, Deref, DerefMut)]
pub struct PamAppHandle<'c, C: PamRawConvImpl = ()> {
    #[deref]
    #[deref_mut]
    handle: PamHandle,
    conv_data: PhantomData<&'c mut C>,
    conv_meta: Option<NonNull<pam_conv>>,
    end: bool,
}

enum RawOrHeap {
    Raw(*const pam_conv),
    Heap(Box<pam_conv>),
}

impl<'c> PamAppHandle<'c, ()> {
    pub fn start_without_conv(service_name: &str, user: &str) -> PamResult<Self> {
        unsafe { Self::start_with_raw_conv(service_name, user, NULL_CONV.as_ptr()) }
    }

    /// # Safety
    ///
    /// `raw_conv` should be a valid `pam_conv` and kept along with the
    /// lifecycle of the handle.
    pub unsafe fn start_with_raw_conv(
        service_name: &str,
        user: &str,
        raw_conv: *const pam_conv,
    ) -> PamResult<Self> {
        static CONV_DATA: () = ();
        Self::do_start_with_raw_conv_ptr(service_name, user, RawOrHeap::Raw(raw_conv), &CONV_DATA)
    }
}

impl<'c, C: PamRawConvImpl> PamAppHandle<'c, C> {
    pub fn start(service_name: &str, user: &str, conv: &'c mut C) -> PamResult<Self> {
        let conv_meta = Box::new(pam_conv {
            conv: Some(custom_conv_callback),
            appdata_ptr: (conv as *mut C).cast(),
        });
        Self::do_start_with_raw_conv_ptr(service_name, user, RawOrHeap::Heap(conv_meta), conv)
    }

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

    pub fn end(mut self, code: PamRawErrorCode) -> PamResult<()> {
        self.do_end(code)
    }

    fn do_start_with_raw_conv_ptr(
        service_name: &str,
        user: &str,
        conv_meta: RawOrHeap,
        _conv_data: &'c C,
    ) -> PamResult<Self> {
        let service_name = CString::from_str(service_name)?;
        let user = CString::from_str(user)?;

        let (conv_meta, raw_conv) = match conv_meta {
            RawOrHeap::Raw(raw_conv) => (None, raw_conv),
            RawOrHeap::Heap(meta) => {
                let ptr = NonNull::from(Box::leak(meta));
                (Some(ptr), ptr.as_ptr() as *const _)
            }
        };

        let mut pamh = null_mut::<pam_handle_t>();
        unsafe {
            pam_res_from_code(pam_start(
                service_name.as_ptr(),
                user.as_ptr(),
                raw_conv,
                &mut pamh,
            ))?;
        }
        Ok(Self {
            handle: unsafe { PamHandle::from_ptr(pamh.cast())? },
            conv_meta,
            conv_data: PhantomData,
            end: false,
        })
    }

    fn do_end(&mut self, code: PamRawErrorCode) -> PamResult<()> {
        if !self.end {
            self.end = true;
            pam_res_from_code(unsafe { pam_end(self.as_ptr_mut().cast(), code as _) })?;
        }
        Ok(())
    }
}

impl<'c, C: PamRawConvImpl> Drop for PamAppHandle<'c, C> {
    fn drop(&mut self) {
        let _ = self.do_end(PamRawErrorCode::Abort);
        if let Some(ptr) = self.conv_meta.take() {
            drop(Box::from(ptr));
        }
    }
}
