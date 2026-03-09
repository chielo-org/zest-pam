use core::ffi::c_int;

use derive_more::{Display, Error};

use crate::PamRawErrorCode;

pub type PamResult<T> = Result<T, PamError>;

#[derive(Debug, Display, Error)]
#[non_exhaustive]
pub enum PamError {
    #[display("null pointer as pam handle")]
    PamHandleNullPtr,
    #[display("pam error: {code}")]
    PamError { code: PamRawErrorCode },
    #[display("unknown message style: {code}")]
    UnknownMessageStyle { code: i32 },
    #[display("unknown error: {code}")]
    UnknownError { code: i32 },
    #[display("no conversation callback is set")]
    NoConv,
    #[display("conversation response is a null point")]
    NullResp,
}

impl PamError {
    #[inline]
    pub fn from_code(code: c_int) -> Option<Self> {
        match PamRawErrorCode::try_from(code) {
            Ok(PamRawErrorCode::Success) => None,
            Ok(code) => Some(PamError::PamError { code }),
            Err(e) => Some(e),
        }
    }

    #[inline]
    pub(crate) const fn unknown_error(code: i32) -> Self {
        Self::UnknownError { code }
    }

    #[inline]
    pub(crate) const fn unknown_message_style(code: i32) -> Self {
        PamError::UnknownMessageStyle { code }
    }
}

#[inline]
pub fn pam_res_from_code(code: c_int) -> PamResult<()> {
    if let Some(e) = PamError::from_code(code) {
        Err(e)
    } else {
        Ok(())
    }
}
