use std::{
    ffi::{CStr, CString, c_int, c_void},
    ptr::null_mut,
};

use zest_pam_core::{
    PamMessageStyle, PamRawErrorCode,
    ffi::{pam_conv, pam_message, pam_response},
};

use crate::PamRawConvImpl;

impl PamRawConvImpl for () {
    #[inline]
    fn on_conv(
        &mut self,
        _style: PamMessageStyle,
        _msg: Option<&CStr>,
    ) -> Result<CString, PamRawErrorCode> {
        Err(PamRawErrorCode::ConvErr)
    }
}

pub(crate) static NULL_CONV: NullConv = NullConv(pam_conv {
    conv: Some(null_conv_callback),
    appdata_ptr: null_mut(),
});

pub(crate) struct NullConv(pam_conv);

impl NullConv {
    #[inline]
    pub const fn as_ptr(&'static self) -> *const pam_conv {
        &self.0
    }
}

unsafe impl Sync for NullConv {}

unsafe extern "C" fn null_conv_callback(
    _num_msg: c_int,
    _msg: *mut *const pam_message,
    _resp: *mut *mut pam_response,
    _appdata_ptr: *mut c_void,
) -> c_int {
    PamRawErrorCode::ConvErr as _
}
