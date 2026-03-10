use core::{
    ffi::CStr,
    ptr::{NonNull, null_mut},
    str::FromStr,
};

use alloc::{borrow::ToOwned, ffi::CString, string::String};
use derive_more::Display;
use libc::{free, strlen};
use num_enum::TryFromPrimitive;
use zeroize::Zeroize;

use crate::{PamError, PamRawHandle, PamResult, ffi::*, pam_res_from_code};

#[repr(i32)]
#[derive(Clone, Copy, Debug, Display, PartialEq, Eq, PartialOrd, Ord, Hash, TryFromPrimitive)]
#[num_enum(error_type(name = PamError, constructor = PamError::unknown_message_style))]
pub enum PamMessageStyle {
    #[display("prompt echo off")]
    PromptEchoOff = PAM_PROMPT_ECHO_OFF,
    #[display("prompt echo on")]
    PromptEchoOn = PAM_PROMPT_ECHO_ON,
    #[display("error message")]
    ErrorMsg = PAM_ERROR_MSG,
    #[display("text info")]
    TextInfo = PAM_TEXT_INFO,
}

impl PamRawHandle {
    pub fn call_conv(&mut self, style: PamMessageStyle, msg: &str) -> PamResult<String> {
        let msg = CString::from_str(msg)?;
        let res = unsafe { self.raw_call_conv(style, &msg) }?;
        Ok(res.into_string()?)
    }

    /// # Safety
    ///
    /// `msg` shall not be a reference backed by a null pointer.
    pub unsafe fn raw_call_conv(
        &mut self,
        style: PamMessageStyle,
        msg: &CStr,
    ) -> PamResult<CString> {
        let conv_ptr = unsafe { self.get_item(PAM_CONV) }?;
        let conv = unsafe { (conv_ptr.cast::<pam_conv>() as *mut pam_conv).as_mut() }
            .ok_or(PamError::NoConv)?;

        let cb = conv.conv.ok_or(PamError::NoConv)?;

        let msg = pam_message {
            msg_style: style as _,
            msg: msg.as_ptr(),
        };
        let mut msg_container = &msg as *const _;

        let mut resp_ptr = null_mut();

        let code = unsafe { (cb)(1, &mut msg_container, &mut resp_ptr, conv.appdata_ptr) };
        pam_res_from_code(code)?;

        let resp_ptr = NonNull::new(resp_ptr).ok_or(PamError::NullResp)?;
        let _resp_ptr_guard = ReleaseGuard(resp_ptr, size_of::<pam_response>());

        let resp = unsafe { resp_ptr.as_ref() };

        let resp_str = NonNull::new(resp.resp).ok_or(PamError::NullResp)?;
        let _resp_str_guard = ReleaseGuard(resp_str, unsafe { strlen(resp_str.as_ptr()) });

        pam_res_from_code(resp.resp_retcode)?;

        Ok(unsafe { CStr::from_ptr(resp_str.as_ptr()) }.to_owned())
    }
}

struct ReleaseGuard<T>(NonNull<T>, usize);

impl<T> Drop for ReleaseGuard<T> {
    fn drop(&mut self) {
        unsafe {
            let raw_bytes = core::slice::from_raw_parts_mut(self.0.as_ptr().cast::<u8>(), self.1);
            raw_bytes.zeroize();
            free(self.0.as_ptr().cast());
        }
    }
}
