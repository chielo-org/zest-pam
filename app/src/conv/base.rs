use std::{
    ffi::{CStr, CString},
    str::FromStr,
};

use zeroize::Zeroizing;
use zest_pam_core::{PamMessageStyle, PamRawErrorCode};

pub trait PamRawConvImpl {
    fn on_conv(
        &mut self,
        style: PamMessageStyle,
        msg: Option<&CStr>,
    ) -> Result<CString, PamRawErrorCode>;
}

pub trait PamAppConvImpl {
    fn on_prompt_echo_off(&mut self, msg: Option<&str>) -> Result<String, PamRawErrorCode>;
    fn on_prompt_echo_on(&mut self, msg: Option<&str>) -> Result<String, PamRawErrorCode>;
    fn on_error_msg(&mut self, msg: Option<&str>) -> Result<String, PamRawErrorCode>;
    fn on_text_info(&mut self, msg: Option<&str>) -> Result<String, PamRawErrorCode>;
}

impl<T: PamAppConvImpl> PamRawConvImpl for T {
    fn on_conv(
        &mut self,
        style: PamMessageStyle,
        msg: Option<&CStr>,
    ) -> Result<CString, PamRawErrorCode> {
        let msg = msg
            .map(|c| c.to_str())
            .transpose()
            .map_err(|_| PamRawErrorCode::ConvErr)?;
        let res = Zeroizing::new(match style {
            PamMessageStyle::PromptEchoOff => self.on_prompt_echo_off(msg)?,
            PamMessageStyle::PromptEchoOn => self.on_prompt_echo_on(msg)?,
            PamMessageStyle::ErrorMsg => self.on_error_msg(msg)?,
            PamMessageStyle::TextInfo => self.on_text_info(msg)?,
        });
        CString::from_str(&res).map_err(|_| PamRawErrorCode::ConvErr)
    }
}
