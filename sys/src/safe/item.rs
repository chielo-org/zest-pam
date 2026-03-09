use core::{
    ffi::{CStr, c_int, c_void},
    ptr::null,
};

use crate::{PamResult, RawPamHandle, ffi::*, pam_res_from_code};

macro_rules! c_str_item_methods {
    ($getter:ident, $setter:ident, $item_type:ident) => {
        #[inline]
        pub fn $getter(&self) -> PamResult<Option<&CStr>> {
            unsafe { self.get_item($item_type) }.map(|ptr| {
                if ptr.is_null() {
                    None
                } else {
                    Some(unsafe { CStr::from_ptr(ptr.cast()) })
                }
            })
        }

        #[inline]
        pub fn $setter(&mut self, item: &CStr) -> PamResult<()> {
            unsafe { self.set_item($item_type, item.as_ptr().cast()) }
        }
    };
}

impl RawPamHandle {
    /// # Safety
    ///
    /// The returned pointer is owned by the underlay `pam_handle_t`.
    #[inline]
    pub unsafe fn get_item(&self, item_type: i32) -> PamResult<*const c_void> {
        let mut item: *const c_void = null();
        pam_res_from_code(unsafe { pam_get_item(self.into(), item_type as c_int, &mut item) })?;
        Ok(item)
    }

    /// # Safety
    ///
    /// The pointer should be valid.
    #[inline]
    pub unsafe fn set_item(&mut self, item_type: i32, item: *const c_void) -> PamResult<()> {
        pam_res_from_code(unsafe { pam_set_item(self.into(), item_type as c_int, item) })
    }

    c_str_item_methods!(get_user, set_user, PAM_USER);
    c_str_item_methods!(get_service, set_service, PAM_SERVICE);
    c_str_item_methods!(get_tty, set_tty, PAM_TTY);
    c_str_item_methods!(get_rhost, set_rhost, PAM_RHOST);
    c_str_item_methods!(get_ruser, set_ruser, PAM_RUSER);
    c_str_item_methods!(get_user_prompt, set_user_prompt, PAM_USER_PROMPT);
    c_str_item_methods!(get_authtok, set_authtok, PAM_AUTHTOK);
    c_str_item_methods!(get_oldauthtok, set_oldauthtok, PAM_OLDAUTHTOK);
}
