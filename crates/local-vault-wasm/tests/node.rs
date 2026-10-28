//! The local server as the extension uses it: from JavaScript, on a file system that answers
//! with promises. Run with `wasm-pack test --node crates/local-vault-wasm`.

#![cfg(target_arch = "wasm32")]

use js_sys::{Array, JSON, Promise, Reflect, Uint8Array};
use local_vault_wasm::{
    JsFileSystem, JsPlatform, WasmLocalServer, check_file_system, flags_that_must_be_off,
    is_answered,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::wasm_bindgen_test;

#[wasm_bindgen(inline_js = r#"
const key = (path) => path.join("/");
const inside = (path, directory) =>
  directory.length === 0 || path.startsWith(key(directory) + "/");

export function memoryFileSystem() {
  const files = new Map();
  return {
    files,
    async list(directory) {
      const names = new Set();
      for (const path of files.keys()) {
        if (inside(path, directory)) {
          names.add(path.split("/")[directory.length]);
        }
      }
      return [...names];
    },
    async exists(path) {
      return files.has(key(path)) || [...files.keys()].some((p) => inside(p, path));
    },
    async read(path) {
      return files.get(key(path)) ?? null;
    },
    async write(path, content) {
      files.set(key(path), content.slice());
    },
    async rename(path, newName) {
      const content = files.get(key(path));
      if (content === undefined) {
        return false;
      }
      files.delete(key(path));
      files.set(key([...path.slice(0, -1), newName]), content);
      return true;
    },
    async delete(path) {
      for (const p of [...files.keys()]) {
        if (p === key(path) || inside(p, path)) {
          files.delete(p);
        }
      }
      return true;
    },
  };
}

export function unreachableFileSystem() {
  const fail = async () => {
    const error = new Error("The local vault helper is not installed.");
    error.name = "LocalVaultIoError";
    throw error;
  };
  return { list: fail, exists: fail, read: fail, write: fail, rename: fail, delete: fail };
}

// Bytes from another realm, which are not an instance of the Uint8Array here: what Jest gives
// a test, which runs in a context of its own, where Node makes them.
async function foreign(bytes) {
  const vm = await import("node:vm");
  return vm.runInNewContext("Uint8Array.from(values)", { values: [...bytes] });
}

export function foreignFileSystem() {
  const fileSystem = memoryFileSystem();
  const read = fileSystem.read;
  fileSystem.read = async (path) => {
    const content = await read(path);
    return content === null ? null : await foreign(content);
  };
  return fileSystem;
}

export async function withForeignBody(request) {
  return { ...request, body: await foreign(request.body) };
}

export function testPlatform() {
  let next = 0;
  return {
    now: () => 1791720000000,
    randomBytes: (length) => Uint8Array.from({ length }, () => next++ % 256),
    log: () => {},
  };
}

export function request(method, path, body, accessToken, form) {
  const headers = {};
  let content = null;
  if (form != null) {
    headers["Content-Type"] = "application/x-www-form-urlencoded;charset=UTF-8";
    content = new TextEncoder().encode(new URLSearchParams(form).toString());
  } else if (body != null) {
    headers["Content-Type"] = "application/json";
    content = new TextEncoder().encode(JSON.stringify(body));
  }
  if (accessToken != null) {
    headers["Authorization"] = `Bearer ${accessToken}`;
  }
  return { method, url: `https://vault.local.invalid/${path}`, headers, body: content };
}

export function content(method, url, bytes) {
  return { method, url, headers: {}, body: Uint8Array.from(bytes) };
}
"#)]
extern "C" {
    fn memoryFileSystem() -> JsFileSystem;
    fn unreachableFileSystem() -> JsFileSystem;
    fn foreignFileSystem() -> JsFileSystem;
    fn withForeignBody(request: JsValue) -> Promise;
    fn testPlatform() -> JsPlatform;
    fn request(method: &str, path: &str, body: JsValue, token: JsValue, form: JsValue) -> JsValue;
    fn content(method: &str, url: &str, bytes: &[u8]) -> JsValue;
}

const REGISTRATION: &str = r#"{
    "email": "user@example.com",
    "userAsymmetricKeys": {"publicKey": "publicKey", "encryptedPrivateKey": "2.privateKey"},
    "masterPasswordAuthentication": {"masterPasswordAuthenticationHash": "aGFzaA=="},
    "masterPasswordUnlock": {
        "salt": "user@example.com",
        "kdf": {"kdfType": 0, "iterations": 600000},
        "masterKeyWrappedUserKey": "2.userKey"
    }
}"#;

const REGISTER: &str = "identity/accounts/register/finish";

const TOKEN: &str = "identity/connect/token";

const LOGIN: &str = r#"{
    "grant_type": "password",
    "username": "user@example.com",
    "password": "aGFzaA==",
    "client_id": "browser"
}"#;

fn server(file_system: JsFileSystem) -> WasmLocalServer {
    let created = WasmLocalServer::new(
        file_system,
        testPlatform(),
        "browser",
        "device",
        "chrome",
        2,
    );
    let Ok(server) = created else {
        panic!("The server is not created.");
    };
    server
}

fn parse(json: &str) -> JsValue {
    JSON::parse(json).unwrap()
}

fn field(value: &JsValue, key: &str) -> JsValue {
    Reflect::get(value, &JsValue::from_str(key)).unwrap()
}

async fn handle(server: &WasmLocalServer, request: JsValue) -> Result<JsValue, JsValue> {
    JsFuture::from(server.handle(request)).await
}

/// The JSON of the body of a response.
fn text_of(response: &JsValue) -> JsValue {
    parse(&field(response, "text").as_string().unwrap())
}

/// Registers an account, logs in to it, and returns its access token.
async fn log_in(server: &WasmLocalServer) -> JsValue {
    let none = JsValue::UNDEFINED;
    let body = parse(REGISTRATION);
    let registration = request("POST", REGISTER, body, none.clone(), none.clone());
    handle(server, registration).await.unwrap();
    let form = parse(LOGIN);
    let login = request("POST", TOKEN, none.clone(), none, form);
    let login = handle(server, login).await.unwrap();
    field(&text_of(&login), "access_token")
}

#[wasm_bindgen_test]
async fn an_account_is_registered_and_synced_on_the_file_system_of_the_extension() {
    let server = server(memoryFileSystem());
    let none = JsValue::UNDEFINED;
    let body = parse(REGISTRATION);
    let registration = request("POST", REGISTER, body, none.clone(), none.clone());

    let registered = handle(&server, registration).await.unwrap();
    let form = parse(LOGIN);
    let login = request("POST", TOKEN, none.clone(), none.clone(), form);
    let login = handle(&server, login).await.unwrap();
    let token = field(&text_of(&login), "access_token");
    let sync = request("GET", "api/sync", none.clone(), token, none.clone());
    let response = handle(&server, sync).await.unwrap();

    assert_eq!(field(&registered, "code").as_f64(), Some(200.0));
    assert_eq!(field(&login, "code").as_f64(), Some(200.0));
    assert_eq!(field(&response, "code").as_f64(), Some(200.0));
    let content_type = field(&response, "contentType").as_string();
    assert_eq!(
        content_type.as_deref(),
        Some("application/json; charset=utf-8")
    );
    assert!(field(&response, "bytes").is_null());
    let email = field(&field(&text_of(&response), "profile"), "email");
    assert_eq!(email.as_string().as_deref(), Some("user@example.com"));
}

#[wasm_bindgen_test]
async fn the_content_of_an_attachment_is_stored_and_read_by_the_local_server() {
    let server = server(memoryFileSystem());
    let none = JsValue::UNDEFINED;
    let token = log_in(&server).await;
    let item = parse(r#"{"type": 1}"#);
    let cipher = request("POST", "api/ciphers", item, token.clone(), none.clone());
    let cipher = text_of(&handle(&server, cipher).await.unwrap());
    let cipher_id = field(&cipher, "id").as_string().unwrap();
    let path = format!("api/ciphers/{cipher_id}/attachment/v2");
    let upload = request("POST", &path, parse("{}"), token, none);
    let upload = text_of(&handle(&server, upload).await.unwrap());
    let url = field(&upload, "url").as_string().unwrap();

    let put = content("PUT", &url, &[1, 2, 3]);
    let stored = handle(&server, put).await.unwrap();
    let get = content("GET", &url, &[]);
    let read = handle(&server, get).await.unwrap();

    assert_eq!(field(&stored, "code").as_f64(), Some(201.0));
    assert_eq!(field(&read, "code").as_f64(), Some(200.0));
    let content_type = field(&read, "contentType").as_string();
    assert_eq!(content_type.as_deref(), Some("application/octet-stream"));
    let bytes = Uint8Array::new(&field(&read, "bytes")).to_vec();
    assert_eq!(bytes, [1, 2, 3]);
}

#[wasm_bindgen_test]
async fn the_rules_that_the_extension_checks_itself_against_are_there() {
    let scratch = vec!["check".to_owned()];
    let checked = JsValue::from(check_file_system(memoryFileSystem(), scratch));
    let failures = JsFuture::from(Promise::from(checked)).await.unwrap();
    let Ok(flags) = flags_that_must_be_off("browser") else {
        panic!("The client is not known.");
    };
    let key_of = |flag: JsValue| field(&flag, "key").as_string();
    let keys: Vec<String> = Array::from(&flags).iter().filter_map(key_of).collect();

    assert_eq!(Array::from(&failures).length(), 0);
    assert!(keys.iter().any(|key| key == "pm-30110-sdk-sends-api"));
    assert!(is_answered("GET", vec!["sync".to_owned()]));
    assert!(!is_answered("GET", vec!["sends".to_owned()]));
}

#[wasm_bindgen_test]
async fn bytes_from_another_realm_are_read() {
    let server = server(foreignFileSystem());
    let none = JsValue::UNDEFINED;
    let body = parse(REGISTRATION);
    let registration = request("POST", REGISTER, body, none.clone(), none.clone());
    let registration = JsFuture::from(withForeignBody(registration)).await.unwrap();

    let registered = handle(&server, registration).await.unwrap();
    let form = parse(LOGIN);
    let login = request("POST", TOKEN, none.clone(), none, form);
    let login = handle(&server, login).await.unwrap();

    // The body of the request is the account, and the vault folder has it when it is read.
    assert_eq!(field(&registered, "code").as_f64(), Some(200.0));
    assert_eq!(field(&login, "code").as_f64(), Some(200.0));
}

#[wasm_bindgen_test]
async fn a_vault_folder_that_cannot_be_reached_rejects_with_an_io_error() {
    let server = server(unreachableFileSystem());
    let none = JsValue::UNDEFINED;
    let email = parse(r#"{"email": "user@example.com"}"#);
    let path = "identity/accounts/prelogin";
    let pre_login = request("POST", path, email, none.clone(), none);

    let error = handle(&server, pre_login).await.unwrap_err();

    let name = field(&error, "name").as_string();
    let message = field(&error, "message").as_string();
    let helper_missing = "The local vault helper is not installed.";
    assert_eq!(name.as_deref(), Some("LocalVaultIoError"));
    assert_eq!(message.as_deref(), Some(helper_missing));
}

#[wasm_bindgen_test]
async fn a_request_that_is_not_one_is_rejected() {
    let server = server(memoryFileSystem());

    let error = handle(&server, JsValue::from_str("sync")).await;

    assert!(error.is_err());
}
