use std::{
    ffi::{CStr, CString, c_int, c_void},
    mem::forget,
    num::NonZeroUsize,
    panic::catch_unwind,
    ptr::{NonNull, null_mut},
};

use libc::{calloc, free, strdup, strlen};
use zeroize::Zeroize;
use zest_pam_core::{
    PamMessageStyle, PamRawErrorCode, PamRawHandle, PamResult,
    ffi::{PAM_CONV, pam_conv, pam_message, pam_response},
};

pub trait PamRawConvImpl {
    fn on_conv(
        &mut self,
        style: PamMessageStyle,
        msg: Option<&CStr>,
    ) -> Result<CString, PamRawErrorCode>;
}

pub trait PamAppConvExt {
    fn with_app_conv<C: PamRawConvImpl, T, F: FnOnce(&mut Self) -> PamResult<T>>(
        &mut self,
        conv: &mut C,
        func: F,
    ) -> PamResult<T>;
}

impl PamAppConvExt for PamRawHandle {
    fn with_app_conv<C: PamRawConvImpl, T, F: FnOnce(&mut Self) -> PamResult<T>>(
        &mut self,
        conv: &mut C,
        func: F,
    ) -> PamResult<T> {
        let conv = pam_conv {
            conv: Some(custom_conv_callback),
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

unsafe fn custom_conv_with_res(
    num_msg: NonZeroUsize,
    msg: *mut *const pam_message,
    resp: *mut *mut pam_response,
    appdata_ptr: *mut c_void,
) -> Result<(), PamRawErrorCode> {
    use PamRawErrorCode::{BufErr, ConvErr};

    let appdata_ptr =
        unsafe { appdata_ptr.cast::<&mut dyn PamRawConvImpl>().as_mut() }.or_conv_err()?;

    let resp_ptr = unsafe { resp.as_mut() }.or_conv_err()?;
    *resp_ptr = null_mut();

    let messages = {
        let msg_ptr = NonNull::new(msg).or_conv_err()?;
        let msg_slice = unsafe { std::slice::from_raw_parts(msg_ptr.as_ptr(), num_msg.get()) };

        let mut messages = Vec::with_capacity(num_msg.get());
        for &msg in msg_slice {
            let msg = unsafe { msg.as_ref() }.or_conv_err()?;
            let style = PamMessageStyle::try_from(msg.msg_style).map_err(|_| ConvErr)?;
            let content = unsafe { msg.msg.as_ref().map(|m| CStr::from_ptr(m)) };
            messages.push((style, content));
        }
        messages
    };

    let reply_ptr = NonNull::<pam_response>::new(
        unsafe { calloc(num_msg.get(), size_of::<pam_response>()) }.cast(),
    )
    .ok_or(BufErr)?;
    let reply_guard = ReleaseGuard(reply_ptr, num_msg.get() * size_of::<pam_response>());
    let replies = unsafe { std::slice::from_raw_parts_mut(reply_ptr.as_ptr(), num_msg.get()) };

    let mut reply_msg_guards = Vec::with_capacity(num_msg.get());

    for (i, (style, content)) in messages.into_iter().enumerate() {
        let res = appdata_ptr.on_conv(style, content)?;

        let resp = NonNull::new(unsafe { strdup(res.as_ptr()) }).ok_or(BufErr)?;
        reply_msg_guards.push(ReleaseGuard(resp, unsafe { strlen(resp.as_ptr()) }));

        replies[i].resp_retcode = 0;
        replies[i].resp = resp.as_ptr();
    }

    while let Some(guard) = reply_msg_guards.pop() {
        guard.defuse();
    }
    reply_guard.defuse();
    *resp_ptr = reply_ptr.as_ptr();

    Ok(())
}

pub(crate) unsafe extern "C" fn custom_conv_callback(
    num_msg: c_int,
    msg: *mut *const pam_message,
    resp: *mut *mut pam_response,
    appdata_ptr: *mut c_void,
) -> c_int {
    let Some(num_msg) = NonZeroUsize::new(num_msg as _) else {
        return PamRawErrorCode::ConvErr as _;
    };
    let res =
        match catch_unwind(|| unsafe { custom_conv_with_res(num_msg, msg, resp, appdata_ptr) }) {
            Ok(res) => res,
            Err(_) => Err(PamRawErrorCode::Abort),
        };
    if let Err(code) = res {
        code as _
    } else {
        PamRawErrorCode::Success as _
    }
}

trait OrConvErr<T> {
    fn or_conv_err(self) -> Result<T, PamRawErrorCode>;
}

impl<T> OrConvErr<T> for Option<T> {
    fn or_conv_err(self) -> Result<T, PamRawErrorCode> {
        self.ok_or(PamRawErrorCode::ConvErr)
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

impl<T> ReleaseGuard<T> {
    fn defuse(self) {
        forget(self);
    }
}
