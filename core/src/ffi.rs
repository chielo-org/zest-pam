#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

#[cfg(feature = "generate-bindings")]
mod inner {
    include!(concat!(env!("OUT_DIR"), "/", "zest_pam_sys_bindgen.rs"));
}

#[cfg(not(feature = "generate-bindings"))]
mod inner {
    #[cfg(target_os = "linux")]
    mod generated {
        include!("generated/libpam_1_3_1.rs");
    }

    pub use self::generated::*;
}

pub use self::inner::*;
