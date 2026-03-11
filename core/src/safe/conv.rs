use core::{
    ffi::CStr,
    ptr::{NonNull, null_mut},
    str::FromStr,
};

use alloc::{borrow::ToOwned, ffi::CString, string::String};
use derive_more::Display;
use libc::strlen;
use num_enum::TryFromPrimitive;
use zeroize::Zeroizing;

use crate::{
    LibCDropGuard, PamError, PamRawHandle, PamResult, SafeCString, ffi::*, pam_res_from_code,
};

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
    #[inline]
    pub fn call_conv_str(
        &mut self,
        style: PamMessageStyle,
        msg: &str,
    ) -> PamResult<Zeroizing<String>> {
        let msg = SafeCString::new(CString::from_str(msg)?, msg.len());
        let res = self.call_conv(style, &msg)?;
        Ok(res.try_into_string()?)
    }

    pub fn call_conv(&mut self, style: PamMessageStyle, msg: &CStr) -> PamResult<SafeCString> {
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
        let _resp_ptr_guard = LibCDropGuard::new(resp_ptr, size_of::<pam_response>());

        let resp = unsafe { resp_ptr.as_ref() };

        let resp_str = NonNull::new(resp.resp).ok_or(PamError::NullResp)?;
        let resp_len = unsafe { strlen(resp_str.as_ptr()) };
        let _resp_str_guard = LibCDropGuard::new(resp_str, resp_len);

        pam_res_from_code(resp.resp_retcode)?;

        Ok(SafeCString::new(
            unsafe { CStr::from_ptr(resp_str.as_ptr()) }.to_owned(),
            resp_len,
        ))
    }
}
