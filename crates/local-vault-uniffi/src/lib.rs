//! The local vault for Kotlin, through UniFFI.
//!
//! The Android app calls [`LocalVaultServer::handle`] from its HTTP client, on a thread of that
//! client, and waits for the answer. The vault folder is reached through the [`VaultFileSystem`]
//! that the app implements, which answers right away, so the server is driven to its end on the
//! thread of the call.
//!
//! The app streams the content of attachments: it leaves the body of a request to an address
//! that [`streams_request_body`] is `true` for out, stores it where the response says, and reads
//! the file that the body of a response is.

use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;

use futures::executor::block_on;
use local_vault::{
    ClientKind, FileSystem, HttpRequest, HttpResponse, IoError, LocalServer, LogLevel, Platform,
    ResponseBody,
};

uniffi::setup_scaffolding!();

/// What can go wrong when the vault folder is used.
#[derive(Debug, uniffi::Error)]
pub enum LocalVaultError {
    /// The vault folder could not be read or written. The app reports it as a request that did
    /// not reach its server.
    Io {
        /// What failed.
        reason: String,
    },
}

impl Display for LocalVaultError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { reason } => f.write_str(reason),
        }
    }
}

impl std::error::Error for LocalVaultError {}

impl From<uniffi::UnexpectedUniFFICallbackError> for LocalVaultError {
    fn from(error: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Io {
            reason: error.reason,
        }
    }
}

impl From<IoError> for LocalVaultError {
    fn from(error: IoError) -> Self {
        Self::Io {
            reason: error.message().to_owned(),
        }
    }
}

/// The vault folder, as the app reaches it. Paths are lists of names relative to the folder.
/// See [`local_vault::FileSystem`] for what each operation does.
#[uniffi::export(callback_interface)]
pub trait VaultFileSystem: Send + Sync {
    /// The names of the entries of a directory, or none if it does not exist.
    fn list(&self, directory: Vec<String>) -> Result<Vec<String>, LocalVaultError>;

    /// Whether a file or a directory exists.
    fn exists(&self, path: Vec<String>) -> Result<bool, LocalVaultError>;

    /// The content of a file, or `null` if there is no file.
    fn read(&self, path: Vec<String>) -> Result<Option<Vec<u8>>, LocalVaultError>;

    /// Replaces the content of a file, creating the directories that are missing.
    fn write(&self, path: Vec<String>, content: Vec<u8>) -> Result<(), LocalVaultError>;

    /// Renames an entry within its directory. `false` if it was not renamed.
    fn rename(&self, path: Vec<String>, new_name: String) -> Result<bool, LocalVaultError>;

    /// Deletes an entry, with everything in it. `true` if nothing remains.
    fn delete(&self, path: Vec<String>) -> Result<bool, LocalVaultError>;
}

/// What the local server needs of the app apart from the vault folder.
#[uniffi::export(callback_interface)]
pub trait VaultPlatform: Send + Sync {
    /// The current time, in milliseconds since the epoch.
    fn now_millis(&self) -> i64;

    /// Logs a message, which never holds anything that is in a vault or in a request.
    fn log(&self, level: VaultLogLevel, message: String);
}

/// How much something that the local server logs matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum VaultLogLevel {
    /// Something to look at, such as a request that is refused.
    Warning,
    /// Something that went wrong.
    Error,
}

/// The client that the local server answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum VaultClientKind {
    /// The Android app.
    Android,
    /// The browser extension.
    Browser,
}

impl From<VaultClientKind> for ClientKind {
    fn from(client: VaultClientKind) -> Self {
        match client {
            VaultClientKind::Android => ClientKind::Android,
            VaultClientKind::Browser => ClientKind::Browser,
        }
    }
}

/// A request, as the HTTP client of the app would have sent it to a Bitwarden server.
#[derive(Debug, Clone, uniffi::Record)]
pub struct VaultRequest {
    /// The HTTP method.
    pub method: String,
    /// The address, such as `https://vault.local.invalid/api/sync`.
    pub url: String,
    /// The headers, with their names in whatever case. `Content-Type` is one of them.
    pub headers: HashMap<String, String>,
    /// The body, which is left out of a request to an address that [`streams_request_body`] is
    /// `true` for.
    pub body: Vec<u8>,
}

/// The body of a response.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum VaultResponseBody {
    /// No body.
    Empty,
    /// JSON.
    Json {
        /// The JSON.
        json: String,
    },
    /// The content of the file at the path of the vault folder, which exists.
    File {
        /// The path of the file.
        path: Vec<String>,
    },
}

/// A response of the local server.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VaultResponse {
    /// The HTTP status code.
    pub code: u16,
    /// The media type of the body, or `null` if there is no body.
    pub content_type: Option<String>,
    /// The body.
    pub body: VaultResponseBody,
    /// Where the app has to store the body of the request, as it comes in, before it gives the
    /// response to its caller. A request whose body cannot be stored fails.
    pub store_request_body_at: Option<Vec<String>>,
}

/// The local server, which answers the requests of the app in place of a Bitwarden server.
#[derive(uniffi::Object)]
pub struct LocalVaultServer {
    server: LocalServer<AppFileSystem, AppPlatform>,
}

#[uniffi::export]
impl LocalVaultServer {
    /// A local server on the vault folder that the file system reaches, for the installation of
    /// the app with the ID: the UUID that the app identifies itself to a Bitwarden server with,
    /// which is the same every time. The app writes its changes to a directory of the vault
    /// folder named after it, which no other device writes.
    ///
    /// Fails with [`LocalVaultError::Io`] if the ID cannot be the name of a directory, as the
    /// local server would write nothing with it: every request that changes the vault would fail.
    #[uniffi::constructor]
    pub fn new(
        file_system: Box<dyn VaultFileSystem>,
        platform: Box<dyn VaultPlatform>,
        client: VaultClientKind,
        device_id: String,
    ) -> Result<Arc<Self>, LocalVaultError> {
        let file_system = AppFileSystem(file_system);
        let platform = AppPlatform(platform);
        let server = LocalServer::new(file_system, platform, client.into(), &device_id)?;
        Ok(Arc::new(Self { server }))
    }

    /// Answers a request. Requests are handled one at a time: a call waits for the one before
    /// it. Fails only if the vault folder cannot be reached.
    pub fn handle(&self, request: VaultRequest) -> Result<VaultResponse, LocalVaultError> {
        let request = HttpRequest {
            method: request.method,
            url: request.url,
            headers: request.headers.into_iter().collect(),
            body: request.body,
        };
        let response = block_on(self.server.handle_http(request))?;
        Ok(to_vault_response(response))
    }
}

/// A feature flag that the local vault counts on to be off.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VaultFlagRule {
    /// The name of the flag.
    pub key: String,
    /// What the app does when the flag is on.
    pub reason: String,
}

/// Returns `true` if the name can be used as the name of a file or a directory in the vault
/// folder: the local vault never uses another one.
#[uniffi::export]
pub fn is_safe_segment(name: String) -> bool {
    local_vault::is_safe_segment(&name)
}

/// The host of the addresses of the local vault, which never resolves.
#[uniffi::export]
pub fn local_vault_host() -> String {
    local_vault::LOCAL_VAULT_HOST.to_owned()
}

/// Returns `true` if the address is one of the local vault, which no request may leave the
/// device for.
#[uniffi::export]
pub fn is_local_vault_url(url: String) -> bool {
    local_vault::is_local_vault_url(&url)
}

/// Returns `true` if the local server does not read the body of a request to the address: it is
/// the content of an attachment, which the app stores where the response says.
#[uniffi::export]
pub fn streams_request_body(url: String) -> bool {
    local_vault::streams_request_body(&url)
}

/// The body of the response that the app gives when a call of the local server fails in a way
/// that the local server does not answer.
#[uniffi::export]
pub fn internal_error_json() -> String {
    local_vault::INTERNAL_ERROR_JSON.to_owned()
}

/// Returns `true` if the local server answers the request, and does not refuse it as a feature
/// that needs a Bitwarden server. The path is relative to the service, with a UUID wherever the
/// ID of an item or a folder goes.
#[uniffi::export]
pub fn is_answered(method: String, path: Vec<String>) -> bool {
    let path: Vec<&str> = path.iter().map(String::as_str).collect();
    local_vault::is_answered(&method, &path)
}

/// The feature flags of the client that the local vault counts on to be off.
#[uniffi::export]
pub fn flags_that_must_be_off(client: VaultClientKind) -> Vec<VaultFlagRule> {
    let client = ClientKind::from(client);
    let rules = local_vault::FLAGS_THAT_MUST_BE_OFF.iter();
    let rules = rules.filter(|rule| rule.clients.contains(&client));
    let rules = rules.map(|rule| VaultFlagRule {
        key: rule.key.to_owned(),
        reason: rule.reason.to_owned(),
    });
    rules.collect()
}

/// The accounts that the vault folder of the source has and that of the target does not, which
/// the app copies when the vault moves to the target.
#[uniffi::export]
pub fn accounts_missing_in(
    source: Box<dyn VaultFileSystem>,
    target: Box<dyn VaultFileSystem>,
) -> Result<Vec<String>, LocalVaultError> {
    let source = AppFileSystem(source);
    let target = AppFileSystem(target);
    let missing = block_on(local_vault::accounts_missing_in(&source, &target))?;
    Ok(missing)
}

/// The files that the app copies of the accounts that the vault folders of both the source and
/// the target have, when the vault moves to the target, as the installation of the app with the
/// ID: the content of attachments that the target does not have, and the files that the app
/// wrote last in its own directory of the account. Each is a path from the vault folder, in the
/// order in which they are copied.
#[uniffi::export]
pub fn device_files_missing_in(
    source: Box<dyn VaultFileSystem>,
    target: Box<dyn VaultFileSystem>,
    device_id: String,
) -> Result<Vec<Vec<String>>, LocalVaultError> {
    let source = AppFileSystem(source);
    let target = AppFileSystem(target);
    let missing = local_vault::device_files_missing_in(&source, &target, &device_id);
    Ok(block_on(missing)?)
}

/// Checks that the file system keeps the rules that the local vault counts on, in the directory
/// at the path `scratch`, which is deleted with everything in it before and after. Returns the
/// rules that it does not keep.
#[uniffi::export]
pub fn check_file_system(
    file_system: Box<dyn VaultFileSystem>,
    scratch: Vec<String>,
) -> Vec<String> {
    let file_system = AppFileSystem(file_system);
    let scratch: Vec<&str> = scratch.iter().map(String::as_str).collect();
    block_on(local_vault::check_file_system(&file_system, &scratch))
}

fn to_vault_response(response: HttpResponse) -> VaultResponse {
    let body = match response.body {
        ResponseBody::Empty => VaultResponseBody::Empty,
        ResponseBody::Json(json) => VaultResponseBody::Json { json },
        ResponseBody::File(path) => VaultResponseBody::File { path },
    };
    VaultResponse {
        code: response.status,
        content_type: response.content_type.map(str::to_owned),
        body,
        store_request_body_at: response.store_request_body_at,
    }
}

fn owned(path: &[&str]) -> Vec<String> {
    path.iter().map(|name| (*name).to_owned()).collect()
}

fn io_error(error: LocalVaultError) -> IoError {
    IoError::new(error.to_string())
}

/// The vault folder that the app reaches, as the local server uses it.
struct AppFileSystem(Box<dyn VaultFileSystem>);

impl FileSystem for AppFileSystem {
    async fn list(&self, directory: &[&str]) -> Result<Vec<String>, IoError> {
        self.0.list(owned(directory)).map_err(io_error)
    }

    async fn exists(&self, path: &[&str]) -> Result<bool, IoError> {
        self.0.exists(owned(path)).map_err(io_error)
    }

    async fn read(&self, path: &[&str]) -> Result<Option<Vec<u8>>, IoError> {
        self.0.read(owned(path)).map_err(io_error)
    }

    async fn write(&self, path: &[&str], content: &[u8]) -> Result<(), IoError> {
        let content = content.to_vec();
        self.0.write(owned(path), content).map_err(io_error)
    }

    async fn rename(&self, path: &[&str], new_name: &str) -> Result<bool, IoError> {
        let new_name = new_name.to_owned();
        self.0.rename(owned(path), new_name).map_err(io_error)
    }

    async fn delete(&self, path: &[&str]) -> Result<bool, IoError> {
        self.0.delete(owned(path)).map_err(io_error)
    }
}

/// The platform of the app, with the random bytes of the operating system.
struct AppPlatform(Box<dyn VaultPlatform>);

impl Platform for AppPlatform {
    fn now_millis(&self) -> i64 {
        self.0.now_millis()
    }

    fn random_bytes(&self, buffer: &mut [u8]) {
        // The operating system always has random bytes for an app: there is nothing to do
        // without them, as every salt and ID would be the same.
        if let Err(error) = getrandom::fill(buffer) {
            panic!("No random bytes: {error}");
        }
    }

    fn log(&self, level: LogLevel, message: &str) {
        let level = match level {
            LogLevel::Warning => VaultLogLevel::Warning,
            LogLevel::Error => VaultLogLevel::Error,
        };
        self.0.log(level, message.to_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::FutureExt;
    use local_vault::MemoryFileSystem;
    use std::sync::Mutex;

    /// The vault folder of a test, as an app would implement it: with calls that answer right
    /// away, which the memory of a test does.
    struct MemoryCallback(MemoryFileSystem);

    fn strs(path: &[String]) -> Vec<&str> {
        path.iter().map(String::as_str).collect()
    }

    /// Takes the result of a call of the file system of a test, which is ready at once. It must
    /// not be waited for with an executor, as the server already runs in one.
    fn ready<T>(call: impl Future<Output = Result<T, IoError>>) -> Result<T, LocalVaultError> {
        match call.now_or_never() {
            Some(result) => Ok(result?),
            None => Err(LocalVaultError::Io {
                reason: "The file system of the test is not ready.".to_owned(),
            }),
        }
    }

    impl VaultFileSystem for MemoryCallback {
        fn list(&self, directory: Vec<String>) -> Result<Vec<String>, LocalVaultError> {
            ready(self.0.list(&strs(&directory)))
        }

        fn exists(&self, path: Vec<String>) -> Result<bool, LocalVaultError> {
            ready(self.0.exists(&strs(&path)))
        }

        fn read(&self, path: Vec<String>) -> Result<Option<Vec<u8>>, LocalVaultError> {
            ready(self.0.read(&strs(&path)))
        }

        fn write(&self, path: Vec<String>, content: Vec<u8>) -> Result<(), LocalVaultError> {
            ready(self.0.write(&strs(&path), &content))
        }

        fn rename(&self, path: Vec<String>, new_name: String) -> Result<bool, LocalVaultError> {
            ready(self.0.rename(&strs(&path), &new_name))
        }

        fn delete(&self, path: Vec<String>) -> Result<bool, LocalVaultError> {
            ready(self.0.delete(&strs(&path)))
        }
    }

    struct Clock(Mutex<Vec<String>>);

    impl VaultPlatform for Clock {
        fn now_millis(&self) -> i64 {
            1_791_720_000_000
        }

        fn log(&self, _level: VaultLogLevel, message: String) {
            if let Ok(mut logs) = self.0.lock() {
                logs.push(message);
            }
        }
    }

    fn request(method: &str, path: &str, body: &str) -> VaultRequest {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_owned(), "application/json".to_owned());
        VaultRequest {
            method: method.to_owned(),
            url: format!("https://vault.local.invalid{path}"),
            headers,
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn the_app_registers_and_reads_the_vault_through_its_own_file_system() {
        let fs = MemoryFileSystem::new();
        let file_system = Box::new(MemoryCallback(fs.clone()));
        let platform = Box::new(Clock(Mutex::new(Vec::new())));
        let device = "11111111-2222-4333-8444-555555555555";
        let android = VaultClientKind::Android;
        let created = LocalVaultServer::new(file_system, platform, android, device.to_owned());
        let Ok(server) = created else {
            panic!("The server is not created.");
        };
        let registration = r#"{
            "email": "user@example.com",
            "userAsymmetricKeys": {"publicKey": "a", "encryptedPrivateKey": "b"},
            "masterPasswordAuthentication": {"masterPasswordAuthenticationHash": "aGFzaA=="},
            "masterPasswordUnlock": {
                "salt": "user@example.com",
                "kdf": {"kdfType": 0, "iterations": 600000},
                "masterKeyWrappedUserKey": "c"
            }
        }"#;

        let register = "/identity/accounts/register/finish";
        let registered = server.handle(request("POST", register, registration));
        let hint = r#"{"email": "user@example.com"}"#;
        let hint = server.handle(request("POST", "/api/accounts/password-hint", hint));

        let Ok(registered) = registered else {
            panic!("The account is not registered.");
        };
        let json = Some("application/json; charset=utf-8".to_owned());
        assert_eq!(registered.code, 200);
        assert_eq!(registered.content_type, json);
        assert_eq!(hint.ok().map(|response| response.code), Some(429));
        // The vault is in the file of the device, and `vault.json` of the account only says
        // which layout it has.
        let paths = fs.paths();
        assert_eq!(paths.len(), 2);
        let is_of_device = |path: &Vec<String>| path.get(2).is_some_and(|name| name == device);
        assert!(paths.iter().any(is_of_device));
    }

    #[test]
    fn no_server_is_created_for_a_device_id_that_cannot_be_the_name_of_a_directory() {
        for device in ["", "..", "a/b", "a b"] {
            let file_system = Box::new(MemoryCallback(MemoryFileSystem::new()));
            let platform = Box::new(Clock(Mutex::new(Vec::new())));
            let android = VaultClientKind::Android;
            let created = LocalVaultServer::new(file_system, platform, android, device.to_owned());
            assert!(created.is_err(), "{device}");
        }
    }

    #[test]
    fn the_rules_that_the_app_checks_itself_against_are_there() {
        let fs = Box::new(MemoryCallback(MemoryFileSystem::new()));
        let scratch = vec!["check".to_owned()];
        let flags = flags_that_must_be_off(VaultClientKind::Android);
        let keys: Vec<&str> = flags.iter().map(|flag| flag.key.as_str()).collect();

        assert!(check_file_system(fs, scratch).is_empty());
        assert!(keys.contains(&"pm-27060-password-prelogin-from-sdk"));
        assert!(!keys.contains(&"pm-30110-sdk-sends-api"));
        assert!(is_answered("GET".to_owned(), vec!["sync".to_owned()]));
        assert!(!is_answered("GET".to_owned(), vec!["sends".to_owned()]));
    }
}
