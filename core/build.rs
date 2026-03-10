use anyhow::Result;

fn main() -> Result<()> {
    println!("cargo:rustc-link-lib=pam");

    #[cfg(feature = "generate-bindings")]
    generate_bindings::generate()?;

    Ok(())
}

#[cfg(feature = "generate-bindings")]
mod generate_bindings {
    use std::path::PathBuf;

    use anyhow::{Context, Result, bail};

    pub(super) fn generate() -> Result<()> {
        println!("cargo:rerun-if-env-changed=PAM_INCLUDE_DIR");
        let pam_include_dir = std::env::var_os("PAM_INCLUDE_DIR")
            .map(PathBuf::from)
            .unwrap_or(PathBuf::from("/usr/include"));
        if !pam_include_dir.join("security/pam_appl.h").exists() {
            bail!("No PAM headers. Please install the development package of `libpam`.");
        }

        let out_dir = PathBuf::from(
            std::env::var_os("OUT_DIR").context("the env var `OUT_DIR` does not exist?")?,
        );

        let wrapper_dir = {
            let mut dir = PathBuf::from(
                std::env::var_os("CARGO_MANIFEST_DIR")
                    .context("the env var `CARGO_MANIFEST_DIR` does not exist?")?,
            );
            dir.push("wrappers");
            dir
        };

        let wrapper_header_path = wrapper_dir.join("libpam.h");

        println!("cargo:rerun-if-changed={}", wrapper_header_path.display());

        bindgen::builder()
            .header(wrapper_header_path.to_string_lossy())
            .use_core()
            .size_t_is_usize(true)
            .default_macro_constant_type(bindgen::MacroTypeVariation::Signed)
            .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
            .layout_tests(true)
            .generate_comments(true)
            .opaque_type("pam_handle_t")
            .blocklist_type("va_list")
            .blocklist_type("__va_list")
            .blocklist_type("__builtin_va_list")
            .blocklist_type("__gnuc_va_list")
            .blocklist_type("__va_list_tag")
            .allowlist_var("PAM_.*")
            .allowlist_function("pam_.*")
            .blocklist_function("pam_v.*")
            .blocklist_function("pam_sm_*")
            .generate()?
            .write_to_file(out_dir.join("zest_pam_sys_bindgen.rs"))?;

        Ok(())
    }
}
