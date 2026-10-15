//! The local vault for JavaScript, through WebAssembly.
//!
//! The browser extension creates a [`WasmLocalServer`] on the file system that reaches its vault
//! folder, and hands it every request for the host of the local vault. The file system answers
//! with promises, as it reaches the folder through messages to another program.
//!
//! The extension has the content of an attachment in memory, so the local server stores it and
//! reads it itself, while no other request is handled.

use std::rc::Rc;

use js_sys::{Array, Error, Object, Promise, Reflect, Uint8Array};
use local_vault::{ClientKind, FileSystem, HttpRequest, IoError, LocalServer, LogLevel, Platform};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{JsFuture, future_to_promise};

/// The name of the errors of a vault folder that cannot be reached, which the extension reports
/// as a request that did not reach its server.
const IO_ERROR_NAME: &str = "LocalVaultIoError";

/// What a vault folder that cannot be reached fails with when the file system does not say why.
const UNREACHABLE_MESSAGE: &str = "The vault folder cannot be reached.";

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &str = r#"
/**
 * The vault folder. Paths are lists of names relative to it. Every operation rejects with an
 * error if the folder cannot be reached.
 */
export interface LocalVaultFileSystem {
  list(directory: string[]): Promise<string[]>;
  exists(path: string[]): Promise<boolean>;
  read(path: string[]): Promise<Uint8Array | null>;
  write(path: string[], content: Uint8Array): Promise<void>;
  rename(path: string[], newName: string): Promise<boolean>;
  delete(path: string[]): Promise<boolean>;
}

/** What the local server needs of the extension apart from the vault folder. None may throw. */
export interface LocalVaultPlatform {
  /** The current time, in milliseconds since the epoch. */
  now(): number;
  /** Random bytes, fit for a salt. */
  randomBytes(length: number): Uint8Array;
  log(level: "warning" | "error", message: string): void;
}

/**
 * A request, as the extension would have sent it to a Bitwarden server: its address, such as
 * `https://vault.local.invalid/api/sync`, and its headers, with their names in whatever case.
 */
export interface LocalVaultRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: Uint8Array | null;
}

/**
 * A response. `contentType` is the media type of the body, `text` the body if it is JSON, and
 * `bytes` the body if it is the encrypted content of an attachment.
 */
export interface LocalVaultResponse {
  code: number;
  contentType: string | null;
  text: string | null;
  bytes: Uint8Array | null;
}

/** A feature flag that the local vault counts on to be off, and what the app does if it is on. */
export interface LocalVaultFlagRule {
  key: string;
  reason: string;
}
"#;

#[wasm_bindgen]
extern "C" {
    /// The vault folder, as the extension reaches it.
    #[wasm_bindgen(typescript_type = "LocalVaultFileSystem")]
    pub type JsFileSystem;

    #[wasm_bindgen(method, catch)]
    fn list(this: &JsFileSystem, directory: &Array) -> Result<Promise, JsValue>;

    #[wasm_bindgen(method, catch)]
    fn exists(this: &JsFileSystem, path: &Array) -> Result<Promise, JsValue>;

    #[wasm_bindgen(method, catch)]
    fn read(this: &JsFileSystem, path: &Array) -> Result<Promise, JsValue>;

    #[wasm_bindgen(method, catch)]
    fn write(this: &JsFileSystem, path: &Array, content: &Uint8Array) -> Result<Promise, JsValue>;

    #[wasm_bindgen(method, catch)]
    fn rename(this: &JsFileSystem, path: &Array, new_name: &str) -> Result<Promise, JsValue>;

    #[wasm_bindgen(method, catch)]
    fn delete(this: &JsFileSystem, path: &Array) -> Result<Promise, JsValue>;

    /// What the local server needs of the extension apart from the vault folder.
    #[wasm_bindgen(typescript_type = "LocalVaultPlatform")]
    pub type JsPlatform;

    #[wasm_bindgen(method)]
    fn now(this: &JsPlatform) -> f64;

    #[wasm_bindgen(method, js_name = randomBytes)]
    fn random_bytes(this: &JsPlatform, length: u32) -> Uint8Array;

    #[wasm_bindgen(method)]
    fn log(this: &JsPlatform, level: &str, message: &str);

    /// The feature flags that the local vault counts on to be off.
    #[wasm_bindgen(typescript_type = "LocalVaultFlagRule[]")]
    pub type FlagRules;

    /// What the checks of a file system come to: the rules that it does not keep.
    #[wasm_bindgen(typescript_type = "Promise<string[]>")]
    pub type BrokenRules;
}

/// The local server, which answers the requests of the extension in place of a Bitwarden server.
#[wasm_bindgen(js_name = LocalServer)]
pub struct WasmLocalServer {
    server: Rc<LocalServer<HostFileSystem, HostPlatform>>,
}

#[wasm_bindgen(js_class = LocalServer)]
impl WasmLocalServer {
    /// A local server on the vault folder that the file system reaches, for the client, which
    /// is `"browser"` or `"android"`.
    #[wasm_bindgen(constructor)]
    pub fn new(
        file_system: JsFileSystem,
        platform: JsPlatform,
        #[wasm_bindgen(unchecked_param_type = "\"browser\" | \"android\"")] client: &str,
    ) -> Result<WasmLocalServer, JsError> {
        let client = client_kind(client)?;
        let file_system = HostFileSystem(file_system);
        let server = LocalServer::new(file_system, HostPlatform(platform), client);
        Ok(Self {
            server: Rc::new(server),
        })
    }

    /// Answers a `LocalVaultRequest` with a `LocalVaultResponse`. Requests are handled one at a
    /// time, the content of an attachment included: one that comes while another one is handled
    /// waits for it. Rejects with an error named `LocalVaultIoError` if the vault folder cannot
    /// be reached, and with nothing else for a request that is one.
    #[wasm_bindgen(unchecked_return_type = "Promise<LocalVaultResponse>")]
    pub fn handle(
        &self,
        #[wasm_bindgen(unchecked_param_type = "LocalVaultRequest")] request: JsValue,
    ) -> Promise {
        let server = Rc::clone(&self.server);
        future_to_promise(async move {
            let request = to_request(&request)?;
            match server.handle_http_buffered(request).await {
                Ok(response) => Ok(to_js_response(&response)),
                Err(error) => Err(to_js_error(&error)),
            }
        })
    }
}

/// Returns `true` if the name can be used as the name of a file or a directory in the vault
/// folder: the local vault never uses another one.
#[wasm_bindgen(js_name = isSafeSegment)]
pub fn is_safe_segment(name: &str) -> bool {
    local_vault::is_safe_segment(name)
}

/// The host of the addresses of the local vault, which never resolves.
#[wasm_bindgen(js_name = localVaultHost)]
pub fn local_vault_host() -> String {
    local_vault::LOCAL_VAULT_HOST.to_owned()
}

/// Returns `true` if the address is one of the local vault, which no request may leave the
/// browser for.
#[wasm_bindgen(js_name = isLocalVaultUrl)]
pub fn is_local_vault_url(url: &str) -> bool {
    local_vault::is_local_vault_url(url)
}

/// The body of the response that the extension gives when a call of the local server fails in a
/// way that the local server does not answer, which may leave it unusable: the extension takes
/// it before.
#[wasm_bindgen(js_name = internalErrorJson)]
pub fn internal_error_json() -> String {
    local_vault::INTERNAL_ERROR_JSON.to_owned()
}

/// Returns `true` if the local server answers the request, and does not refuse it as a feature
/// that needs a Bitwarden server. The path is relative to the service, with a UUID wherever the
/// ID of an item or a folder goes.
#[wasm_bindgen(js_name = isAnswered)]
pub fn is_answered(method: &str, path: Vec<String>) -> bool {
    let path: Vec<&str> = path.iter().map(String::as_str).collect();
    local_vault::is_answered(method, &path)
}

/// The feature flags of the client, which is `"browser"` or `"android"`, that the local vault
/// counts on to be off.
#[wasm_bindgen(js_name = flagsThatMustBeOff)]
pub fn flags_that_must_be_off(
    #[wasm_bindgen(unchecked_param_type = "\"browser\" | \"android\"")] client: &str,
) -> Result<FlagRules, JsError> {
    let client = client_kind(client)?;
    let rules = local_vault::FLAGS_THAT_MUST_BE_OFF.iter();
    let rules = rules.filter(|rule| rule.clients.contains(&client));
    let rules = rules.map(|rule| {
        let fields = [("key", rule.key), ("reason", rule.reason)];
        JsValue::from(to_object(fields.map(|(key, value)| (key, value.into()))))
    });
    Ok(rules.collect::<Array>().unchecked_into())
}

/// Checks that the file system keeps the rules that the local vault counts on, in the directory
/// at the path `scratch`, which is deleted with everything in it before and after. Resolves to
/// the rules that it does not keep.
#[wasm_bindgen(js_name = checkFileSystem)]
pub fn check_file_system(file_system: JsFileSystem, scratch: Vec<String>) -> BrokenRules {
    let checked = future_to_promise(async move {
        let file_system = HostFileSystem(file_system);
        let scratch: Vec<&str> = scratch.iter().map(String::as_str).collect();
        let failures = local_vault::check_file_system(&file_system, &scratch).await;
        Ok(to_array(&failures).into())
    });
    checked.unchecked_into()
}

fn client_kind(client: &str) -> Result<ClientKind, JsError> {
    match client {
        "android" => Ok(ClientKind::Android),
        "browser" => Ok(ClientKind::Browser),
        _ => Err(JsError::new("The client is \"browser\" or \"android\".")),
    }
}

fn to_request(value: &JsValue) -> Result<HttpRequest, JsValue> {
    let field = |key: &str| Reflect::get(value, &JsValue::from_str(key));
    let method = field("method")?
        .as_string()
        .ok_or_else(|| JsError::new("A request needs a method."))?;
    let url = field("url")?
        .as_string()
        .ok_or_else(|| JsError::new("A request needs an address."))?;
    let body = bytes(&field("body")?).unwrap_or_default();
    Ok(HttpRequest {
        method,
        url,
        headers: to_pairs(&field("headers")?),
        body,
    })
}

/// The bytes of a `Uint8Array`, or `None` if the value is not an object.
///
/// Values are told apart by what they are and not by their class: one from another realm is not
/// an instance of the classes here. Jest runs a test in a context of its own, where what Node
/// makes, such as the bytes from a `TextEncoder`, is from the realm outside of it.
fn bytes(value: &JsValue) -> Option<Vec<u8>> {
    value.is_object().then(|| Uint8Array::new(value).to_vec())
}

/// The names and the values of an object of strings, such as the headers of a request.
fn to_pairs(value: &JsValue) -> Vec<(String, String)> {
    if !value.is_object() {
        return Vec::new();
    }
    let mut pairs = Vec::new();
    for entry in Object::entries(value.unchecked_ref()).iter() {
        let entry = Array::from(&entry);
        if let (Some(key), Some(value)) = (entry.get(0).as_string(), entry.get(1).as_string()) {
            pairs.push((key, value));
        }
    }
    pairs
}

fn to_js_response(response: &local_vault::BufferedResponse) -> JsValue {
    let or_null = |value: Option<&str>| value.map_or(JsValue::NULL, JsValue::from_str);
    let bytes = match &response.bytes {
        Some(bytes) => Uint8Array::from(bytes.as_slice()).into(),
        None => JsValue::NULL,
    };
    let fields = [
        ("code", JsValue::from(response.status)),
        ("contentType", or_null(response.content_type)),
        ("text", or_null(response.text.as_deref())),
        ("bytes", bytes),
    ];
    to_object(fields).into()
}

/// A new object with the fields.
fn to_object<const N: usize>(fields: [(&str, JsValue); N]) -> Object {
    let object = Object::new();
    for (key, value) in fields {
        // Setting a field of a new object cannot fail.
        let _ = Reflect::set(&object, &JsValue::from_str(key), &value);
    }
    object
}

fn to_js_error(error: &IoError) -> JsValue {
    let js_error = Error::new(error.message());
    js_error.set_name(IO_ERROR_NAME);
    js_error.into()
}

fn to_array<S: AsRef<str>>(path: &[S]) -> Array {
    path.iter()
        .map(|name| JsValue::from_str(name.as_ref()))
        .collect()
}

/// The error of the file system as one of the local vault, with the message that it has.
fn to_io_error(error: JsValue) -> IoError {
    let message = Reflect::get(&error, &JsValue::from_str("message"))
        .ok()
        .and_then(|message| message.as_string());
    IoError::new(message.as_deref().unwrap_or(UNREACHABLE_MESSAGE))
}

async fn settle(promise: Result<Promise, JsValue>) -> Result<JsValue, IoError> {
    let promise = promise.map_err(to_io_error)?;
    JsFuture::from(promise).await.map_err(to_io_error)
}

/// The vault folder that the extension reaches, as the local server uses it.
struct HostFileSystem(JsFileSystem);

impl FileSystem for HostFileSystem {
    async fn list(&self, directory: &[&str]) -> Result<Vec<String>, IoError> {
        let names = settle(self.0.list(&to_array(directory))).await?;
        let names = Array::from(&names);
        Ok(names.iter().filter_map(|name| name.as_string()).collect())
    }

    async fn exists(&self, path: &[&str]) -> Result<bool, IoError> {
        let exists = settle(self.0.exists(&to_array(path))).await?;
        Ok(exists.as_bool() == Some(true))
    }

    async fn read(&self, path: &[&str]) -> Result<Option<Vec<u8>>, IoError> {
        let content = settle(self.0.read(&to_array(path))).await?;
        Ok(bytes(&content))
    }

    async fn write(&self, path: &[&str], content: &[u8]) -> Result<(), IoError> {
        let content = Uint8Array::from(content);
        settle(self.0.write(&to_array(path), &content)).await?;
        Ok(())
    }

    async fn rename(&self, path: &[&str], new_name: &str) -> Result<bool, IoError> {
        let renamed = settle(self.0.rename(&to_array(path), new_name)).await?;
        Ok(renamed.as_bool() == Some(true))
    }

    async fn delete(&self, path: &[&str]) -> Result<bool, IoError> {
        let deleted = settle(self.0.delete(&to_array(path))).await?;
        Ok(deleted.as_bool() == Some(true))
    }
}

/// The platform of the extension.
struct HostPlatform(JsPlatform);

impl Platform for HostPlatform {
    fn now_millis(&self) -> i64 {
        // A time in milliseconds is an integer far below 2^53.
        self.0.now() as i64
    }

    fn random_bytes(&self, buffer: &mut [u8]) {
        let length = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        let bytes = self.0.random_bytes(length).to_vec();
        for (byte, random) in buffer.iter_mut().zip(bytes) {
            *byte = random;
        }
    }

    fn log(&self, level: LogLevel, message: &str) {
        let level = match level {
            LogLevel::Warning => "warning",
            LogLevel::Error => "error",
        };
        self.0.log(level, message);
    }
}
