use core::{
    ffi::CStr,
    ptr::{NonNull, null_mut},
};

use alloc::{borrow::ToOwned, ffi::CString};
use derive_more::Display;
use libc::free;
use num_enum::TryFromPrimitive;

use crate::{PamError, PamResult, RawPamHandle, ffi::*, pam_res_from_code};

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

struct OwnedPtrGuard<T>(NonNull<T>);

impl<T> Drop for OwnedPtrGuard<T> {
    fn drop(&mut self) {
        unsafe {
            free(self.0.as_ptr().cast());
        }
    }
}

impl RawPamHandle {
    pub fn call_conv(&mut self, style: PamMessageStyle, msg: &CStr) -> PamResult<CString> {
        let conv_ptr = unsafe { self.get_item(PAM_CONV) }?;
        let mut conv =
            NonNull::new(conv_ptr.cast::<pam_conv>() as *mut pam_conv).ok_or(PamError::NoConv)?;
        let conv = unsafe { conv.as_mut() };

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
        let _resp_ptr_guard = OwnedPtrGuard(resp_ptr);

        let resp = unsafe { resp_ptr.as_ref() };

        let resp_str = NonNull::new(resp.resp).ok_or(PamError::NullResp)?;
        let _resp_str_guard = OwnedPtrGuard(resp_str);

        pam_res_from_code(resp.resp_retcode)?;

        Ok(unsafe { CStr::from_ptr(resp_str.as_ptr()) }.to_owned())
    }
}

// TODO: move idiomatic conv to a independent crate for applications, where the
// Box<dyn PamConv> should be owned by the handle, where the lifecycle should be
// fully managed. trait PamConv {
//     fn call_conv<'a>(&'a mut self, msg: PamMessage<'_>) -> Result<Cow<'a,
// str>, PamRawErrorCode>; }
//
//
// extern "C" fn rust_pam_conv(
//     num_msg: c_int,
//     msg: *mut *const pam_message,
//     resp: *mut *mut pam_response,
//     appdata_ptr: *mut ::core::ffi::c_void,
// ) -> c_int {
//     if resp.is_null() {
//         return PamRawErrorCode::ConvErr as _;
//     }
//     unsafe {
//         *resp = null_mut();
//     }
//
//     let Some(appdata_ptr) = NonNull::new(appdata_ptr.cast::<Box<dyn
// PamConv>>()) else {         return PamRawErrorCode::ConvErr as _;
//     };
//
//     if msg.is_null() || appdata_ptr.is_null() {
//         return PamRawErrorCode::ConvErr as _;
//     }
//
//     // let appdata =
//     //
//     // let raw_msg = unsafe { slice::from_raw_parts(msg.cast_const(), num_msg
// as _)     // }; // TODO: parse messages
//     //
//     // let Some(resp_ptr) = NonNull::new(unsafe { calloc(num_msg as _,
//     // size_of::<pam_response>()) }) else {
//     //     return PamRawErrorCode::ConvErr as _;
//     // };
//     // let guard = RespPtrGuard(resp_ptr);
//     //
//     // let responses = unsafe { slice::from_raw_parts_mut(resp_ptr.as_ptr(),
// num_msg     // as _) };
//     //
//     // guard.defuse();
//     // unsafe {
//     //     *resp = ;
//     // }
//     PamRawErrorCode::Success as _
// }
