//! The local server as the extension uses it: from JavaScript, on a file system that answers
//! with promises. Run with `wasm-pack test --node crates/local-vault-wasm`.

#![cfg(target_arch = "wasm32")]

use js_sys::{JSON, Reflect};
use local_vault_wasm::{JsFileSystem, JsPlatform, WasmLocalServer};
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

export function testPlatform() {
  let next = 0;
  return {
    now: () => 1791720000000,
    randomBytes: (length) => Uint8Array.from({ length }, () => next++ % 256),
    log: () => {},
  };
}

export function request(method, path, body, accessToken, form) {
  return {
    method,
    path: path.split("/"),
    accessToken: accessToken ?? null,
    form: form ?? {},
    query: {},
    body: body === undefined ? null : new TextEncoder().encode(JSON.stringify(body)),
  };
}
"#)]
extern "C" {
    fn memoryFileSystem() -> JsFileSystem;
    fn unreachableFileSystem() -> JsFileSystem;
    fn testPlatform() -> JsPlatform;
    fn request(method: &str, path: &str, body: JsValue, token: JsValue, form: JsValue) -> JsValue;
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

const LOGIN: &str = r#"{
    "grant_type": "password",
    "username": "user@example.com",
    "password": "aGFzaA==",
    "client_id": "browser"
}"#;

fn server(file_system: JsFileSystem) -> WasmLocalServer {
    let Ok(server) = WasmLocalServer::new(file_system, testPlatform(), "browser") else {
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

#[wasm_bindgen_test]
async fn an_account_is_registered_and_synced_on_the_file_system_of_the_extension() {
    let server = server(memoryFileSystem());
    let none = JsValue::UNDEFINED;
    let path = "accounts/register/finish";
    let body = parse(REGISTRATION);
    let registration = request("POST", path, body, none.clone(), none.clone());

    let registered = handle(&server, registration).await.unwrap();
    let form = parse(LOGIN);
    let login = request("POST", "connect/token", none.clone(), none.clone(), form);
    let login = handle(&server, login).await.unwrap();
    let login_body = parse(&field(&login, "json").as_string().unwrap());
    let token = field(&login_body, "access_token");
    let sync = request("GET", "sync", none.clone(), token, none.clone());
    let response = handle(&server, sync).await.unwrap();

    assert_eq!(field(&registered, "code").as_f64(), Some(200.0));
    assert_eq!(field(&login, "code").as_f64(), Some(200.0));
    assert_eq!(field(&response, "code").as_f64(), Some(200.0));
    assert!(field(&response, "file").is_null());
    assert!(field(&response, "storeRequestBodyAt").is_null());
    let sync = parse(&field(&response, "json").as_string().unwrap());
    let email = field(&field(&sync, "profile"), "email");
    assert_eq!(email.as_string().as_deref(), Some("user@example.com"));
}

#[wasm_bindgen_test]
async fn a_vault_folder_that_cannot_be_reached_rejects_with_an_io_error() {
    let server = server(unreachableFileSystem());
    let none = JsValue::UNDEFINED;
    let email = parse(r#"{"email": "user@example.com"}"#);
    let pre_login = request("POST", "accounts/prelogin", email, none.clone(), none);

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
