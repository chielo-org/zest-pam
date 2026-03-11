#![cfg(feature = "safe-wrappers")]

mod conv;
mod error;
mod handle;
mod item;
mod raw_error_code;
mod util;

pub use ::{libc, zeroize};

pub use self::{
    conv::PamMessageStyle,
    error::{PamError, PamNulError, PamResult, PamUtf8Error, pam_res_from_code},
    handle::{PamHandle, PamRawHandle},
    raw_error_code::PamRawErrorCode,
    util::{LibCDropGuard, SafeCString},
};
