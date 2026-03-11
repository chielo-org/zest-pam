use zest_pam_core::{
    PamRawHandle, PamResult,
    ffi::{PAM_CONV, pam_conv},
};

use crate::{PamRawConvImpl, conv::callback::pam_raw_conv_callback};

pub trait PamHandleConvExt {
    fn with_conv<C: PamRawConvImpl, T, F: FnOnce(&mut Self) -> PamResult<T>>(
        &mut self,
        conv: &mut C,
        func: F,
    ) -> PamResult<T>;
}

impl PamHandleConvExt for PamRawHandle {
    fn with_conv<C: PamRawConvImpl, T, F: FnOnce(&mut Self) -> PamResult<T>>(
        &mut self,
        conv: &mut C,
        func: F,
    ) -> PamResult<T> {
        let conv = pam_conv {
            conv: Some(pam_raw_conv_callback),
            appdata_ptr: (conv as *mut C).cast(),
        };
        let old_conv_ptr = unsafe { self.get_item(PAM_CONV) }?;
        unsafe {
            self.set_item(PAM_CONV, ((&conv) as *const pam_conv).cast())?;
        }
        let res = func(self);
        unsafe {
            self.set_item(PAM_CONV, old_conv_ptr)?;
        }
        res
    }
}
