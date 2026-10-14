//! The local vault for JavaScript, through WebAssembly.
//!
//! The browser extension creates a [`WasmLocalServer`] on the file system that reaches its vault
//! folder, and hands it every request for the host of the local vault. The file system answers
//! with promises, as it reaches the folder through messages to another program.

use std::collections::HashMap;
use std::rc::Rc;

use js_sys::{Array, Error, Object, Promise, Reflect, Uint8Array};
use local_vault::{
    ClientKind, FileSystem, IoError, LocalRequest, LocalResponse, LocalServer, LogLevel, Platform,
    ResponseBody,
};
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

/** A request, as the extension would have sent it to a Bitwarden server. */
export interface LocalVaultRequest {
  method: string;
  path: string[];
  accessToken: string | null;
  form: Record<string, string>;
  query: Record<string, string>;
  body: Uint8Array | null;
}

/**
 * A response. `json` is the body for `application/json`, `file` the path of the file whose
 * content is the body for `application/octet-stream`, and `storeRequestBodyAt` the path of the
 * file that the body of the request has to be written to before the response is given.
 */
export interface LocalVaultResponse {
  code: number;
  json: string | null;
  file: string[] | null;
  storeRequestBodyAt: string[] | null;
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
        client: &str,
    ) -> Result<WasmLocalServer, JsError> {
        let client = match client {
            "android" => ClientKind::Android,
            "browser" => ClientKind::Browser,
            _ => return Err(JsError::new("The client is \"browser\" or \"android\".")),
        };
        let file_system = HostFileSystem(file_system);
        let server = LocalServer::new(file_system, HostPlatform(platform), client);
        Ok(Self {
            server: Rc::new(server),
        })
    }

    /// Answers a `LocalVaultRequest` with a `LocalVaultResponse`. Requests are handled one at a
    /// time: one that comes while another one is handled waits for it. Rejects with an error
    /// named `LocalVaultIoError` if the vault folder cannot be reached, and with nothing else.
    pub fn handle(&self, request: JsValue) -> Promise {
        let server = Rc::clone(&self.server);
        future_to_promise(async move {
            let request = to_request(&request)?;
            match server.handle(&request).await {
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

/// The first segment of the path of a request for the content of an attachment, whose body is
/// not read by the local server but stored by the extension.
#[wasm_bindgen(js_name = attachmentsPath)]
pub fn attachments_path() -> String {
    local_vault::ATTACHMENTS_PATH.to_owned()
}

fn to_request(value: &JsValue) -> Result<LocalRequest, JsValue> {
    let field = |key: &str| Reflect::get(value, &JsValue::from_str(key));
    let method = field("method")?
        .as_string()
        .ok_or_else(|| JsError::new("A request needs a method."))?;
    let path = Array::from(&field("path")?)
        .iter()
        .filter_map(|segment| segment.as_string())
        .collect();
    let body = field("body")?;
    let body = if body.is_instance_of::<Uint8Array>() {
        Uint8Array::new(&body).to_vec()
    } else {
        Vec::new()
    };
    Ok(LocalRequest {
        method,
        path,
        access_token: field("accessToken")?.as_string(),
        form: to_map(&field("form")?),
        query: to_map(&field("query")?),
        body,
    })
}

fn to_map(value: &JsValue) -> HashMap<String, String> {
    let Some(object) = value.dyn_ref::<Object>() else {
        return HashMap::new();
    };
    let mut map = HashMap::new();
    for entry in Object::entries(object).iter() {
        let entry = Array::from(&entry);
        if let (Some(key), Some(value)) = (entry.get(0).as_string(), entry.get(1).as_string()) {
            map.insert(key, value);
        }
    }
    map
}

fn to_js_response(response: &LocalResponse) -> JsValue {
    let (json, file) = match &response.body {
        ResponseBody::Empty => (JsValue::NULL, JsValue::NULL),
        ResponseBody::Json(json) => (JsValue::from_str(json), JsValue::NULL),
        ResponseBody::File(path) => (JsValue::NULL, to_array(path).into()),
    };
    let store_at = match &response.store_request_body_at {
        Some(path) => to_array(path).into(),
        None => JsValue::NULL,
    };
    let object = Object::new();
    let fields = [
        ("code", JsValue::from(response.code)),
        ("json", json),
        ("file", file),
        ("storeRequestBodyAt", store_at),
    ];
    for (key, value) in fields {
        // Setting a field of a new object cannot fail.
        let _ = Reflect::set(&object, &JsValue::from_str(key), &value);
    }
    object.into()
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
        if !content.is_instance_of::<Uint8Array>() {
            return Ok(None);
        }
        Ok(Some(Uint8Array::new(&content).to_vec()))
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
