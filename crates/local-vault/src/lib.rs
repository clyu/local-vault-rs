//! The local vault of the decentralized Bitwarden clients.
//!
//! The clients work without a Bitwarden server. What a server would have stored is kept in files,
//! the vault folder, and the server itself is replaced by the [`LocalServer`]: a function from a
//! request of the Bitwarden API to its response, which a client calls in place of going to the
//! network. Every client uses this one implementation, so that they all read and write the vault
//! folder the same way. The layout of the folder is specified in `docs/LOCAL_VAULT_FORMAT.md`.
//!
//! What a client brings is the [`FileSystem`] that the vault folder is reached through, the
//! [`Platform`] that tells the time, makes random bytes and logs, and the place where it hands
//! its requests over as an [`HttpRequest`]. What a request asks for is worked out here, and the
//! rules that a client checks itself against are here as well: [`is_answered`] for the requests
//! that it can make, [`FLAGS_THAT_MUST_BE_OFF`] for its feature flags, and
//! [`check_file_system`] for its file system.

// The `json!` literals of a whole vault nest deeper than the default allows.
#![recursion_limit = "256"]

mod account;
mod conformance;
mod date;
mod devices;
mod exchange;
mod fs;
mod http;
mod identity;
mod json;
mod kdf;
mod memory_fs;
mod merge;
mod platform;
mod rotation;
mod server;
mod store;
mod token;
mod vault;
mod verifier;
mod withheld;

pub use conformance::check_file_system;
pub use exchange::{
    BINARY_MEDIA_TYPE, BufferedResponse, HttpRequest, HttpResponse, JSON_MEDIA_TYPE,
    is_local_vault_url, streams_request_body,
};
pub use fs::{FileSystem, IoError};
pub use http::{INTERNAL_ERROR_JSON, LocalRequest, LocalResponse, ResponseBody};
pub use json::is_safe_segment;
pub use memory_fs::MemoryFileSystem;
pub use platform::{LogLevel, Platform};
pub use server::{ClientKind, FLAGS_THAT_MUST_BE_OFF, FlagRule, LocalServer, is_answered};
pub use store::{
    LOCAL_VAULT_FORMAT, LOCAL_VAULT_VERSION, accounts_missing_in, device_files_missing_in,
};
pub use vault::{ATTACHMENTS_PATH, LOCAL_VAULT_HOST};
