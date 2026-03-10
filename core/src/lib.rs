#![no_std]

pub mod ffi;

#[cfg(feature = "safe-wrappers")]
extern crate alloc;

#[cfg(feature = "safe-wrappers")]
mod safe;

#[cfg(feature = "safe-wrappers")]
pub use crate::safe::*;
