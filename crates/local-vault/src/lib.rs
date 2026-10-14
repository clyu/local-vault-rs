//! The local vault of the decentralized Bitwarden clients.
//!
//! The clients work without a Bitwarden server. What a server would have stored is kept in files,
//! the vault folder, and the server itself is replaced by the [`LocalServer`]: a function from a
//! request of the Bitwarden API to its response, which a client calls in place of going to the
//! network. Every client uses this one implementation, so that they all read and write the vault
//! folder the same way. The layout of the folder is specified in `LOCAL_VAULT_FORMAT.md` of the
//! Android app.
//!
//! What a client brings is the [`FileSystem`] that the vault folder is reached through, and the
//! [`Platform`] that tells the time, makes random bytes and logs.

// The `json!` literals of a whole vault nest deeper than the default allows.
#![recursion_limit = "256"]

mod account;
mod date;
mod fs;
mod http;
mod identity;
mod json;
mod memory_fs;
mod platform;
mod server;
mod store;
mod token;
mod vault;
mod verifier;

pub use fs::{FileSystem, IoError};
pub use http::{LocalRequest, LocalResponse, ResponseBody};
pub use json::is_safe_segment;
pub use memory_fs::MemoryFileSystem;
pub use platform::{LogLevel, Platform};
pub use server::{ClientKind, LocalServer};
pub use store::{LOCAL_VAULT_FORMAT, LOCAL_VAULT_VERSION};
pub use vault::{ATTACHMENTS_PATH, LOCAL_VAULT_HOST};
