use core::{ffi::c_int, str::Utf8Error};

use alloc::{ffi::NulError, vec::Vec};
use derive_more::{Display, Error};
use zeroize::Zeroizing;

use crate::{PamRawErrorCode, SafeCString};

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
    #[display("{_0}")]
    InvalidUtf8(#[error(source)] PamUtf8Error),
    #[display("{_0}")]
    InteriorNul(#[error(source)] PamNulError),
    #[display("no conversation callback is set")]
    NoConv,
    #[display("conversation response is a null point")]
    NullResp,
}

#[derive(Debug, Display, Error)]
#[display("nul byte found in provided data at position: {pos}")]
pub struct PamNulError {
    pub value: Zeroizing<Vec<u8>>,
    pub pos: usize,
}

#[derive(Debug, Display, Error)]
#[display("C string contained non-utf8 bytes")]
pub struct PamUtf8Error {
    pub value: SafeCString,
    #[error(source)]
    pub err: Utf8Error,
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

impl From<NulError> for PamNulError {
    #[inline]
    fn from(e: NulError) -> Self {
        Self {
            pos: e.nul_position(),
            value: Zeroizing::new(e.into_vec()),
        }
    }
}

impl From<PamUtf8Error> for PamError {
    #[inline]
    fn from(value: PamUtf8Error) -> Self {
        Self::InvalidUtf8(value)
    }
}

impl From<PamNulError> for PamError {
    #[inline]
    fn from(value: PamNulError) -> Self {
        Self::InteriorNul(value)
    }
}

impl From<NulError> for PamError {
    #[inline]
    fn from(value: NulError) -> Self {
        Self::InteriorNul(value.into())
    }
}
