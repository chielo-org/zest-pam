use derive_more::Display;
use num_enum::TryFromPrimitive;

use crate::{PamError, ffi::*};

#[repr(i32)]
#[derive(Clone, Copy, Debug, Display, PartialEq, Eq, PartialOrd, Ord, Hash, TryFromPrimitive)]
#[num_enum(error_type(name = PamError, constructor = PamError::unknown_error))]
pub enum PamRawErrorCode {
    #[display("success")]
    Success = PAM_SUCCESS,
    #[display("failed to load module")]
    OpenErr = PAM_OPEN_ERR,
    #[display("symbol not found")]
    SymbolErr = PAM_SYMBOL_ERR,
    #[display("error in service module")]
    ServiceErr = PAM_SERVICE_ERR,
    #[display("system error")]
    SystemErr = PAM_SYSTEM_ERR,
    #[display("memory buffer error")]
    BufErr = PAM_BUF_ERR,
    #[display("permission denied")]
    PermDenied = PAM_PERM_DENIED,
    #[display("authentication failure")]
    AuthErr = PAM_AUTH_ERR,
    #[display("insufficient credentials")]
    CredInsufficient = PAM_CRED_INSUFFICIENT,
    #[display("authentication information unavailable")]
    AuthinfoUnavail = PAM_AUTHINFO_UNAVAIL,
    #[display("unknown user")]
    UserUnknown = PAM_USER_UNKNOWN,
    #[display("maximum number of tries exceeded")]
    Maxtries = PAM_MAXTRIES,
    #[display("authentication token required")]
    NewAuthtokReqd = PAM_NEW_AUTHTOK_REQD,
    #[display("account expired")]
    AcctExpired = PAM_ACCT_EXPIRED,
    #[display("session error")]
    SessionErr = PAM_SESSION_ERR,
    #[display("credential unavailable")]
    CredUnavail = PAM_CRED_UNAVAIL,
    #[display("credential expired")]
    CredExpired = PAM_CRED_EXPIRED,
    #[display("credential error")]
    CredErr = PAM_CRED_ERR,
    #[display("no module data")]
    NoModuleData = PAM_NO_MODULE_DATA,
    #[display("conversation error")]
    ConvErr = PAM_CONV_ERR,
    #[display("authentication token error")]
    AuthtokErr = PAM_AUTHTOK_ERR,
    #[display("authentication token recovery error")]
    AuthtokRecoveryErr = PAM_AUTHTOK_RECOVERY_ERR,
    #[display("authentication token lock busy")]
    AuthtokLockBusy = PAM_AUTHTOK_LOCK_BUSY,
    #[display("authentication token aging disabled")]
    AuthtokDisableAging = PAM_AUTHTOK_DISABLE_AGING,
    #[display("try again")]
    TryAgain = PAM_TRY_AGAIN,
    #[display("ignore")]
    Ignore = PAM_IGNORE,
    #[display("operation aborted")]
    Abort = PAM_ABORT,
    #[display("authentication token expired")]
    AuthtokExpired = PAM_AUTHTOK_EXPIRED,
    #[display("unknown module")]
    ModuleUnknown = PAM_MODULE_UNKNOWN,
    #[display("bad item")]
    BadItem = PAM_BAD_ITEM,
    #[display("conversation again")]
    ConvAgain = PAM_CONV_AGAIN,
    #[display("incomplete")]
    Incomplete = PAM_INCOMPLETE,
}
