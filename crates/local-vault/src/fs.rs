use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// The vault folder could not be read or written. A client reports it the way it reports a
/// request that did not reach its server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoError {
    message: String,
}

impl IoError {
    /// An error with the given message, which says what failed without naming files of the
    /// device.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// What failed.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl Display for IoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for IoError {}

/// A minimal hierarchical file store that holds the local vault.
///
/// Every path is a list of names relative to the vault folder, so an empty list is the folder
/// itself. The local vault only ever passes names that [`is_safe_segment`] accepts, apart from
/// the names of the files of a vault, which have a `.` in them.
///
/// The operations are asynchronous, as a browser extension reaches the folder through messages
/// to another program. A client whose file system answers right away can implement them as
/// such, and wait for the local server with any executor.
///
/// [`is_safe_segment`]: crate::is_safe_segment
// The futures are not required to be `Send`: those of a browser hold JavaScript values.
#[allow(async_fn_in_trait)]
pub trait FileSystem {
    /// Returns the names of the entries directly inside the directory, or none if the directory
    /// does not exist.
    async fn list(&self, directory: &[&str]) -> Result<Vec<String>, IoError>;

    /// Returns `true` if a file or a directory exists at the path.
    async fn exists(&self, path: &[&str]) -> Result<bool, IoError>;

    /// Returns the content of the file at the path, or `None` if there is no file there.
    async fn read(&self, path: &[&str]) -> Result<Option<Vec<u8>>, IoError>;

    /// Writes the file at the path. Any content that it had is replaced, and any directory that
    /// is missing on the way is created.
    async fn write(&self, path: &[&str], content: &[u8]) -> Result<(), IoError>;

    /// Renames the entry at the path, keeping it in the same directory. Returns `true` if the
    /// entry was renamed. A place that cannot rename an entry over another one returns `false`.
    async fn rename(&self, path: &[&str], new_name: &str) -> Result<bool, IoError>;

    /// Deletes the entry at the path, with everything inside it if it is a directory. Returns
    /// `true` if nothing remains at the path.
    async fn delete(&self, path: &[&str]) -> Result<bool, IoError>;
}
