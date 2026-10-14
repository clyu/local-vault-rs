/// How much something that the local server logs matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// Something that a client may want to look at, such as a request that is refused.
    Warning,
    /// Something that went wrong.
    Error,
}

/// What the local server needs of the platform that it runs on, apart from the vault folder.
pub trait Platform {
    /// The current time, in milliseconds since the epoch.
    fn now_millis(&self) -> i64;

    /// Fills the buffer with random bytes that are fit for a salt and for IDs.
    fn random_bytes(&self, buffer: &mut [u8]);

    /// Logs a message. A message never holds anything that is in a vault or in a request, apart
    /// from the paths of requests without their IDs.
    fn log(&self, level: LogLevel, message: &str);
}

/// Returns a new random UUID (version 4), in lower case.
pub(crate) fn new_uuid(platform: &impl Platform) -> String {
    let mut bytes = [0u8; 16];
    platform.random_bytes(&mut bytes);
    let mut uuid = String::with_capacity(36);
    for (index, byte) in bytes.into_iter().enumerate() {
        let byte = match index {
            // The version, 4.
            6 => (byte & 0x0f) | 0x40,
            // The variant of RFC 9562.
            8 => (byte & 0x3f) | 0x80,
            _ => byte,
        };
        if matches!(index, 4 | 6 | 8 | 10) {
            uuid.push('-');
        }
        uuid.push_str(&format!("{byte:02x}"));
    }
    uuid
}
