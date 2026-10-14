//! Generates the bindings of `local-vault-uniffi` for other languages:
//!
//! ```sh
//! cargo run -p uniffi-bindgen -- generate --library <liblocal_vault_uniffi> --language kotlin \
//!     --out-dir <directory>
//! ```

fn main() {
    uniffi::uniffi_bindgen_main()
}
